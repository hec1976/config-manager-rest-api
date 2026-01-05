#!/usr/bin/env perl
# Config Manager - REST (Mojo-optimiert, actions schema, hardened)
# Version: 1.7.6 (2026-01-05)
#
# OPT 1.7.6:
# - _capture_cmd_promise: sicherer Capture ohne Backticks (open3), Output bleibt 1:1 als combined stdout+stderr
# - write_atomic: nutzt spew statt spurt (Mojo deprecated warning weg)
# - systemctl Base-Argv wird 1x vorbereitet (Flags nicht dauernd shellwords)
# - kleinere Helper fuer Name-Checks und JSON-Errors, weniger Duplikate
# - keine Aenderung am API-Verhalten (Endpoints, JSON-Keys, Status-Logik bleiben gleich)

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::Promise;
use Mojo::Util qw(secure_compare steady_time);
use Mojo::JSON qw(decode_json encode_json);
use Mojo::Date;

use FindBin qw($Bin);
use Net::CIDR ();
use Text::ParseWords qw(shellwords);

use IPC::Open3;
use Symbol qw(gensym);

{
    umask 0007;

    our $VERSION = '1.7.6';

    our $globalfile  = "$Bin/global.json";
    our $configsfile = "$Bin/configs.json";

    our $SYSTEMCTL       = '/usr/bin/systemctl';
    our $SYSTEMCTL_FLAGS = '';

    our $log = Mojo::Log->new;
    $log->level('info');

    our $global = eval { decode_json(path($globalfile)->slurp) };
    die "global.json ungueltig: $@" if $@ || ref($global) ne 'HASH';

    our $configs = eval { decode_json(path($configsfile)->slurp) };
    die "configs.json ungueltig: $@" if $@ || ref($configs) ne 'HASH';

    $SYSTEMCTL = $global->{systemctl}
        if defined $global->{systemctl} && $global->{systemctl} ne '';

    $SYSTEMCTL_FLAGS = exists $ENV{SYSTEMCTL_FLAGS}
        ? $ENV{SYSTEMCTL_FLAGS}
        : (defined $global->{systemctl_flags} ? $global->{systemctl_flags} : '');

    # systemctl argv einmal vorbereiten
    our @SYSTEMCTL_BASE = ($SYSTEMCTL);
    if (defined $SYSTEMCTL_FLAGS && length $SYSTEMCTL_FLAGS) {
        my @f = shellwords($SYSTEMCTL_FLAGS);
        push @SYSTEMCTL_BASE, @f if @f;
    }

    our $logfile = $global->{logfile} // "/var/log/config-manager.log";
    our $logdir  = path($logfile)->dirname;

    unless (-d $logdir) {
        eval { $logdir->make_path; 1 };
        chmod 0755, $logdir->to_string if -d $logdir->to_string;
    }

    if (-d $logdir) {
        $log->path($logfile);
        $log->info("Logging in Datei $logfile aktiviert.");
    } else {
        $log->warn("Konnte Log-Verzeichnis $logdir nicht nutzen. Logging auf STDERR.");
    }

    our $sec = $global->{secret};
    our @secrets = ref($sec) eq 'ARRAY' ? @$sec : ($sec // 'change-this-long-random-secret-please');
    app->secrets(\@secrets);

    if (grep { defined($_) && $_ eq 'change-this-long-random-secret-please' } @secrets) {
        $log->warn('[config-manager] WARNING: Standard-Mojolicious Secret wird verwendet! Bitte in global.json anpassen.');
    }

    our $api_token   = defined $ENV{API_TOKEN} && $ENV{API_TOKEN} ne '' ? $ENV{API_TOKEN} : $global->{api_token};
    our $allowed_ips = $global->{allowed_ips} // [];
    $allowed_ips = [] unless ref($allowed_ips) eq 'ARRAY';

    our $tmpDir     = $global->{tmpDir}    // "$Bin/tmp";
    our $backupRoot = $global->{backupDir} // "$Bin/backup";

    eval { path($backupRoot)->make_path; 1 } or die "Backup-Verzeichnis $backupRoot fehlt/nicht erstellbar";
    chmod 0750, $backupRoot if -d $backupRoot;

    eval { path($tmpDir)->make_path; 1 } or die "Tmp-Verzeichnis $tmpDir fehlt/nicht erstellbar";
    chmod 0750, $tmpDir if -d $tmpDir;

    our $maxBackups          = $global->{maxBackups} // 10;
    our $path_guard          = lc($ENV{PATH_GUARD} // ($global->{path_guard} // 'off'));
    our $apply_meta_enabled  = $global->{apply_meta}          // 0;
    our $auto_create_backups = $global->{auto_create_backups} // 0;

    our @ALLOWED_CANON = ();
    if (ref($global->{allowed_roots}) eq 'ARRAY') {
        my %seen;
        for my $r (@{$global->{allowed_roots}}) {
            for my $cr (_canon_root($r)) {
                next if $seen{$cr}++;
                push @ALLOWED_CANON, $cr;
            }
        }
    }
    if (@ALLOWED_CANON) { $log->info('ALLOWED_ROOTS=' . join(',', @ALLOWED_CANON)); }
    else { $log->info('ALLOWED_ROOTS=(leer)'); }

    # ---------------- Helper klein und zentral ----------------

    sub _bad_name {
        my ($s) = @_;
        return 1 if !defined $s;
        return 1 if $s =~ m{[/\\]};
        return 0;
    }

    sub _json_err {
        my ($c, $code, $msg) = @_;
        $code ||= 400;
        return $c->render(status => $code, json => { ok => 0, error => $msg });
    }

    sub _canon_root {
        my ($p) = @_;
        return () unless defined $p && length $p;
        my $rp = path($p)->realpath;
        return () unless defined $rp && length $rp;
        $rp =~ s{/*$}{};
        $rp .= '/';
        return $rp;
    }

    sub _canon_dir_of_path {
        my ($p) = @_;
        return () unless defined $p && length $p;
        my $rp = -e $p ? path($p)->realpath : path($p)->dirname->realpath;
        return () unless defined $rp && length $rp;
        $rp =~ s{/*$}{};
        $rp .= '/';
        return $rp;
    }

    sub _mode_str {
        my ($p) = @_;
        return undef unless -e $p;
        return sprintf('%04o', (stat($p))[2] & 07777);
    }

    sub _cur_umask {
        my $o = umask();
        umask($o);
        return $o;
    }

    sub _is_allowed_path {
        my ($p) = @_;
        return 0 if -l $p;
        return 1 if $path_guard eq 'off';

        return ($path_guard eq 'audit')
            ? do { $log->warn("PATH-GUARD audit: keine allowed_roots"); 1 }
            : 0
            unless @ALLOWED_CANON;

        my $dircanon = _canon_dir_of_path($p);
        return 0 unless $dircanon;

        for my $root (@ALLOWED_CANON) {
            return 1 if ($dircanon eq $root) || (index($dircanon, $root) == 0);
        }

        if ($path_guard eq 'audit') {
            $log->warn("PATH-GUARD audit: $p ausserhalb allowed_roots");
            return 1;
        }
        return 0;
    }

    sub _name2uid {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getpwnam($n))[2]);
    }

    sub _name2gid {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getgrnam($n))[2]);
    }

    sub _apply_meta {
        my ($e, $p) = @_;

        my $auto_wanted = (defined $e->{user} || defined $e->{group} || defined $e->{mode}) ? 1 : 0;
        my $enabled = defined $e->{apply_meta} ? $e->{apply_meta} : ($apply_meta_enabled || $auto_wanted);

        unless ($enabled) { $log->info("APPLY_META uebersprungen (deaktiviert) fuer Pfad=$p"); return; }

        die "Pfad nicht erlaubt" unless _is_allowed_path($p);
        die "Symlinks werden abgelehnt" if -l $p;

        my $uid = _name2uid($e->{user});
        my $gid = _name2gid($e->{group});

        my $mode;
        if (defined $e->{mode}) {
            my $m = "$e->{mode}";
            $m =~ s/^0+//;
            die "Ungueltiger Modus: $e->{mode}" unless $m =~ /^[0-7]{3,4}$/;
            $mode = oct($m);
        }

        if (defined $uid || defined $gid) {
            my $u = defined($uid) ? $uid : -1;
            my $g = defined($gid) ? $gid : -1;
            chown($u, $g, $p) or die "chown fehlgeschlagen: $!";
        }
        chmod($mode, $p) if defined $mode;
        return;
    }

    sub _backup_dir_for {
        my ($name) = @_;
        my $sub = $name;
        $sub =~ s{[^A-Za-z0-9._-]+}{_}g;
        return "$backupRoot/$sub";
    }

    sub _systemctl_promise {
        my ($timeout, @cmd) = @_;
        $timeout = 30 unless defined $timeout && $timeout =~ /^\d+$/;

        return Mojo::Promise->new(sub {
            my ($resolve, $reject) = @_;

            Mojo::IOLoop->subprocess(
                sub {
                    local $SIG{ALRM} = sub { die "__TIMEOUT__\n" };
                    alarm $timeout;

                    open(STDIN, '<', '/dev/null') or die "open /dev/null: $!";

                    system @cmd;

                    alarm 0;
                    return $?;
                },
                sub {
                    my ($subprocess, $err, $raw_rc) = @_;

                    if (defined $err && length $err) {
                        if ($err =~ /__TIMEOUT__/) {
                            $log->warn("systemctl Timeout nach ${timeout}s: @cmd");
                            return $resolve->(-1);
                        }
                        $log->error("systemctl Subprocess Fehler: $err cmd=@cmd");
                        return $reject->($err);
                    }

                    $raw_rc //= 0;

                    if (($raw_rc & 127) > 0) {
                        my $sig = $raw_rc & 127;
                        $log->warn("systemctl mit Signal $sig beendet: @cmd");
                        return $resolve->(128 + $sig);
                    }

                    my $rc = ($raw_rc >> 8);
                    return $resolve->($rc);
                }
            );
        });
    }

    # sicherer Capture (stdout+stderr kombiniert), ohne Shell
    sub _capture_cmd_promise {
        my ($timeout, @cmd) = @_;
        $timeout = 10 unless defined $timeout && $timeout =~ /^\d+$/;

        return Mojo::Promise->new(sub {
            my ($resolve) = @_;

            Mojo::IOLoop->subprocess(
                sub {
                    local $SIG{ALRM} = sub { die "__TIMEOUT__\n" };
                    alarm $timeout;

                    local $ENV{PATH} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

                    my $errfh = gensym;
                    my $pid = open3(my $in, my $out, $errfh, @cmd);

                    close $in;

                    my $buf = '';
                    while (1) {
                        my $chunk = '';
                        my $r = sysread($out, $chunk, 8192);
                        last unless $r;
                        $buf .= $chunk;
                    }

                    while (1) {
                        my $chunk = '';
                        my $r = sysread($errfh, $chunk, 8192);
                        last unless $r;
                        $buf .= $chunk;
                    }

                    waitpid($pid, 0);
                    my $rc = ($? >> 8);

                    alarm 0;
                    return { rc => $rc, out => ($buf // "") };
                },
                sub {
                    my ($subprocess, $err, $res) = @_;
                    if (defined $err && $err =~ /__TIMEOUT__/) {
                        return $resolve->({ rc => -1, out => "TIMEOUT after ${timeout}s\n" });
                    }
                    $res ||= { rc => -1, out => ($err // "unknown error") };
                    return $resolve->($res);
                }
            );
        });
    }

    our %cfgmap;

    sub _derive_actions {
        my ($entry) = @_;
        my %actions;

        if (ref($entry->{actions}) eq 'HASH') {
            while (my ($k, $v) = each %{$entry->{actions}}) {
                $actions{$k} = (ref($v) eq 'ARRAY') ? [@$v] : [];
            }
            return \%actions;
        }

        if (ref($entry->{commands}) eq 'HASH') {
            while (my ($k, $v) = each %{$entry->{commands}}) {
                $actions{$k} = (ref($v) eq 'ARRAY') ? [@$v] : [];
            }
            return \%actions;
        }

        if (ref($entry->{command_args}) eq 'HASH') {
            my @tokens = ref($entry->{commands}) eq 'ARRAY' ? @{$entry->{commands}} : keys %{$entry->{command_args}};
            for my $t (@tokens) {
                my $arr = $entry->{command_args}{$t};
                $actions{$t} = (ref($arr) eq 'ARRAY') ? [@$arr] : [];
            }
            return \%actions;
        }

        if (ref($entry->{commands}) eq 'ARRAY' && grep { $_ eq 'run' } @{$entry->{commands}}) {
            $actions{run} = [];
        }

        return \%actions;
    }

    sub _rebuild_cfgmap_from {
        my ($cfg) = @_;
        %cfgmap = ();

        while (my ($name, $entry) = each %{$cfg}) {
            next if !defined $name || $name =~ m{[/\\]} || $name =~ m{\.\.};

            my $actions = _derive_actions($entry);

            $cfgmap{$name} = {
                %$entry,
                id         => $name,
                service    => $entry->{service}  // $name,
                category   => $entry->{category} // 'uncategorized',
                path       => $entry->{path},
                actions    => $actions,
                backup_dir => _backup_dir_for($name),
            };
        }
        return;
    }

    sub write_atomic {
        my ($p, $bytes) = @_;
        my $file = path($p);
        my $tmp  = $file->dirname->child(".tmp_" . $file->basename . ".$$");
        $tmp->spew($bytes);
        $tmp->move_to($file);
        return 'atomic';
    }

    sub safe_write_file {
        my ($p, $bytes) = @_;
        my $method = 'atomic';

        my $ok = eval { write_atomic($p, $bytes); 1 };
        if (!$ok) {
            $method = 'plain';
            path($p)->spew($bytes);
        }
        return $method;
    }

    sub parse_postmulti_status {
        my ($stdout, $stderr, $rc) = @_;
        my $txt = lc(($stdout // "") . ($stderr // ""));

        return "running" if $txt =~ /is\s+running/
            || $txt =~ /pid:\s*\d+/
            || $txt =~ /[\w\-\.\/]+:\s*(the\s+postfix\s+mail\s+system\s+is\s+)?running/;

        return "stopped" if $txt =~ /not\s+running/
            || $txt =~ /inactive/
            || $txt =~ /stopped/
            || $txt =~ /[\w\-\.\/]+:\s*not\s+running/;

        return "running" if $rc == 0;
        return "stopped" if $rc == 1;

        return "unknown";
    }

    sub _req_meta {
        my ($c) = @_;
        return {
            req_id => $c->stash('req_id') // '',
            ip     => $c->stash('client_ip') // '',
            method => $c->req->method // '',
            path   => $c->req->url->path->to_string // '',
        };
    }

    sub _fmt_req {
        my ($c) = @_;
        my $m = _req_meta($c);
        return sprintf('req_id=%s ip=%s %s %s', $m->{req_id}, $m->{ip}, $m->{method}, $m->{path});
    }

    our %TRUSTED = map { $_ => 1 } (ref($global->{trusted_proxies}) eq 'ARRAY' ? @{$global->{trusted_proxies}} : ());

    sub _client_ip {
        my ($c) = @_;
        my $rip = $c->tx->remote_address // '';
        if ($TRUSTED{$rip}) {
            my $xff = $c->req->headers->header('X-Forwarded-For') // '';
            if ($xff) {
                my @ips = map { s/^\s+|\s+$//gr } split /,/, $xff;
                return $ips[0] // $rip;
            }
        }
        return $rip;
    }

    our %ALLOW_ORIGIN = map { $_ => 1 } (ref($global->{allow_origins}) eq 'ARRAY' ? @{$global->{allow_origins}} : ());

    # ---------------- ROUTES ----------------

    get '/' => sub {
        my $c = shift;
        my @routes_list;

        foreach my $route (@{app->routes->children}) {
            next unless ref $route;
            my $methods = $route->via;
            my $method_str = (ref $methods eq 'ARRAY' && @$methods)
                ? join(', ', map { uc } @$methods)
                : 'ANY';
            my $p = $route->to_string;
            push @routes_list, { method => $method_str, path => $p };
        }

        @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

        $c->render(json => {
            ok            => 1,
            name          => 'config-manager',
            version       => $VERSION,
            api_endpoints => \@routes_list
        });
    };

    get '/configs' => sub {
        my $c = shift;
        my @list;

        for my $name (sort keys %cfgmap) {
            my $e = $cfgmap{$name};
            my $filename = path($e->{path})->basename;
            my ($ext) = $filename =~ /\.([^.]+)$/;
            my @tokens = sort keys %{$e->{actions} // {}};

            push @list, {
                id       => $name,
                filename => $filename,
                filetype => lc($ext // 'txt'),
                category => $e->{category},
                actions  => \@tokens
            };
        }

        $c->render(json => { ok => 1, configs => \@list });
    };

    get '/config/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return _json_err($c, 400, 'Ungueltiger Name') if _bad_name($name);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannt: $name");
        my $p = $e->{path};

        return _json_err($c, 400, "Pfad nicht erlaubt") unless _is_allowed_path($p);
        return _json_err($c, 404, "Datei fehlt: $p") unless -f $p;

        my $data = path($p)->slurp;
        $c->res->headers->content_type('application/octet-stream');
        $c->render(data => $data);
    };

    post '/config/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return _json_err($c, 400, 'Ungueltiger Name') if _bad_name($name);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannt: $name");
        my $p = $e->{path};

        return _json_err($c, 400, "Pfad nicht erlaubt") unless _is_allowed_path($p);

        my $content = $c->req->body // '';
        if (($c->req->headers->content_type // '') =~ m{application/json}i) {
            my $j = eval { $c->req->json };
            if (!$@ && ref($j) eq 'HASH' && exists $j->{content}) {
                $content = $j->{content} // '';
            }
        }

        my $bdir = $e->{backup_dir};

        unless (-d $bdir) {
            if ($auto_create_backups) {
                eval { path($bdir)->make_path; 1 };
                chmod 0750, $bdir if -d $bdir;
            }
            return _json_err($c, 500, "Backup-Verzeichnis fehlt") unless -d $bdir;
        }

        if (-f $p) {
            my $ts = Mojo::Date->new->to_datetime;
            if ($ts =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
                $ts = "$1$2$3_$4$5$6";
            } else {
                $ts =~ s/[^0-9]//g;
                $ts = substr($ts, 0, 8) . "_" . substr($ts, 8, 6) if length($ts) >= 14;
            }

            my $bfile = "$bdir/" . path($p)->basename . ".bak.$ts";
            eval { path($p)->copy_to($bfile); 1 };

            my @b = sort { $b cmp $a } grep { defined } glob("$bdir/" . path($p)->basename . ".bak.*");
            if (@b > $maxBackups) {
                unlink @b[$maxBackups .. $#b];
            }
        }

        my $method;
        eval { $method = safe_write_file($p, $content); 1 }
            or return _json_err($c, 500, "Schreibfehler: $@");

        my $meta_wanted = defined $e->{apply_meta}
            ? $e->{apply_meta}
            : ($apply_meta_enabled || defined($e->{user}) || defined($e->{group}) || defined($e->{mode}));

        eval { _apply_meta($e, $p); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = _mode_str($p);
        my ($uid, $gid)  = ((stat($p))[4], (stat($p))[5]);

        $c->render(json => {
            ok        => 1,
            saved     => $name,
            path      => $p,
            method    => $method,
            requested => {
                user       => $e->{user},
                group      => $e->{group},
                mode       => $e->{mode},
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false)
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    get '/backups/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return _json_err($c, 400, 'Ungueltiger Name') if _bad_name($name);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannte Konfiguration: $name");
        my $bdir = $e->{backup_dir};

        unless (-d $bdir) {
            return $c->render(json => { ok => 1, backups => [] });
        }

        my $base = path($e->{path})->basename;
        my @files = sort { $b cmp $a } grep { defined } glob("$bdir/$base.bak.*");
        @files = map { s{^\Q$bdir\E/}{}r } @files;
        $c->render(json => { ok => 1, backups => \@files });
    };

    get '/backupcontent/*name/*filename' => sub {
        my $c = shift;
        my $name = $c->stash('name');
        my $filename = $c->stash('filename');

        return _json_err($c, 400, 'Ungueltiger Name/Filename') if _bad_name($name) || _bad_name($filename);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannte Konfiguration: $name");

        my $bdir = $e->{backup_dir};
        my $base = path($e->{path})->basename;

        return _json_err($c, 400, 'Ungueltiger Backup-Name')
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $file = "$bdir/$filename";
        return _json_err($c, 404, 'Backup nicht gefunden') unless -f $file;

        my $content = path($file)->slurp;
        $c->render(json => { ok => 1, content => $content });
    };

    post '/restore/*name/*filename' => sub {
        my $c = shift;
        my $name = $c->stash('name');
        my $filename = $c->stash('filename');

        return _json_err($c, 400, 'Ungueltiger Name/Filename') if _bad_name($name) || _bad_name($filename);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannte Konfiguration: $name");

        my $base = path($e->{path})->basename;
        my $bdir = $e->{backup_dir};

        return _json_err($c, 400, 'Ungueltiger Backup-Name')
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $src  = "$bdir/$filename";
        my $dest = $e->{path};

        return _json_err($c, 404, 'Backup nicht gefunden') unless -f $src;
        return _json_err($c, 400, 'Pfad nicht erlaubt') unless _is_allowed_path($dest);

        path($src)->copy_to($dest)
            or return _json_err($c, 500, "Wiederherstellung fehlgeschlagen: $!");

        eval { _apply_meta($e, $dest); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = _mode_str($dest);
        my ($uid, $gid)  = ((stat($dest))[4], (stat($dest))[5]);

        my $meta_wanted = defined $e->{apply_meta}
            ? $e->{apply_meta}
            : ($apply_meta_enabled || defined($e->{user}) || defined($e->{group}) || defined($e->{mode}));

        $c->render(json => {
            ok       => 1,
            restored => $name,
            from     => $filename,
            requested => {
                user       => $e->{user},
                group      => $e->{group},
                mode       => $e->{mode},
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false)
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    post '/action/*name/*cmd' => sub {
        my $c = shift;
        my ($name, $cmd) = ($c->stash('name'), $c->stash('cmd'));

        return _json_err($c, 400, 'Ungueltige Anfrage') if _bad_name($name);

        my $e = $cfgmap{$name} or return _json_err($c, 404, "Unbekannt");

        my $svc          = $e->{service} // $name;
        my $is_postmulti = ($svc =~ m{^exec:/usr/sbin/postmulti$});
        my $actmap       = $e->{actions};

        return _json_err($c, 400, 'Aktion nicht erlaubt')
            unless ref($actmap) eq 'HASH' && exists $actmap->{$cmd};

        my @extra = @{$actmap->{$cmd}};
        for (@extra) {
            if ($_ !~ /^[A-Za-z0-9._:+@\/=\-,]+$/) {
                return _json_err($c, 400, "Ungueltiges Argument");
            }
        }

        my $action_promise;

        if ($is_postmulti) {
            my ($bin) = ($svc =~ m{^exec:(/.+)$});

            $action_promise = _capture_cmd_promise(30, $bin, @extra)->then(sub {
                my ($res) = @_;

                if ($cmd =~ /^(stop|start|reload|restart)$/) {
                    select(undef, undef, undef, 0.6);
                }

                my @status_args = @{$actmap->{status} // []};
                if (!@status_args) { @status_args = ('-i', $name, '-p', 'status'); }

                return _capture_cmd_promise(10, $bin, @status_args)->then(sub {
                    my ($status_res) = @_;
                    my $state = parse_postmulti_status($status_res->{out}, '', $status_res->{rc});

                    my $ok = 0;
                    if    ($cmd eq 'stop')   { $ok = ($state eq 'stopped') ? 1 : 0; }
                    elsif ($cmd eq 'status') { $ok = 1; }
                    else                     { $ok = ($state eq 'running') ? 1 : 0; }

                    $c->render(json => {
                        ok     => $ok,
                        action => $cmd,
                        status => $state,
                        rc     => $res->{rc},
                        output => $res->{out},
                    });
                });
            });
        }
        elsif ($cmd eq 'daemon-reload') {
            $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, 'daemon-reload')->then(sub {
                my $rc = shift;
                $c->render(json => $rc == 0 ? { ok => 1 } : { ok => 0, error => "Rueckgabewert=$rc" });
            });
        }
        elsif ($svc =~ m{^(bash|sh|perl|exec):(/.+)$}) {
            my ($runner, $script) = ($1, $2);
            return _json_err($c, 404, "Skript nicht gefunden: $script") unless -f $script;

            if ($runner eq 'exec' && $script =~ m{/systemctl$}) {
                return _json_err($c, 400, 'Subcommand verboten')
                    if ($extra[0] // '') =~ /^(poweroff|reboot|halt)$/;
            }

            my @argv =
                  $runner eq 'perl' ? ('/usr/bin/perl', $script, @extra)
                : $runner eq 'bash' ? ('/bin/bash', $script, @extra)
                : $runner eq 'sh'   ? ('/bin/sh',   $script, @extra)
                :                    ($script, @extra);

            $action_promise = _capture_cmd_promise(30, @argv)->then(sub {
                my $res = shift;
                my $rc = $res->{rc};
                if (($extra[0] // '') eq 'is-active') {
                    $c->render(json => { ok => 1, status => ($rc == 0 ? 'running' : 'stopped'), rc => $rc });
                } else {
                    $c->render(json => { ok => ($rc == 0 ? 1 : 0), rc => $rc, output => $res->{out} });
                }
            });
        }
        else {
            if ($cmd eq 'stop_start') {
                $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, 'stop', $svc)
                    ->then(sub { _systemctl_promise(30, @SYSTEMCTL_BASE, 'start', $svc) });
            }
            elsif ($cmd eq 'restart') {
                $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, 'restart', $svc);
            }
            elsif ($cmd eq 'reload') {
                $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, 'is-active', $svc)->then(sub {
                    my $rc = shift;
                    return _systemctl_promise(30, @SYSTEMCTL_BASE, 'reload', $svc) if $rc == 0;
                    die "Dienst nicht aktiv\n";
                });
            }
            elsif ($svc eq 'systemctl') {
                return _json_err($c, 400, 'Verboten') if $cmd =~ /^(poweroff|reboot|halt)$/;
                $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, $cmd, @extra);
            }
            else {
                $action_promise = _systemctl_promise(30, @SYSTEMCTL_BASE, $cmd, $svc);
            }

            $action_promise->then(sub {
                my $rc = shift;
                if ($cmd =~ /^(stop_start|restart|reload|start|stop)$/) {
                    return _systemctl_promise(30, @SYSTEMCTL_BASE, 'is-active', $svc)->then(sub {
                        my $active_rc = shift;
                        $c->render(json => {
                            ok     => ($active_rc == 0 || $cmd eq 'stop' ? 1 : 0),
                            action => $cmd,
                            status => ($active_rc == 0 ? 'running' : 'stopped')
                        });
                    });
                } else {
                    $c->render(json => { ok => ($rc == 0 ? 1 : 0), rc => $rc });
                }
            })->catch(sub {
                my $err = shift;
                $c->render(json => { ok => 0, error => "$err" }, status => 500);
            });

            return;
        }

        $action_promise->catch(sub {
            my ($err) = @_;
            $log->error("Fehler bei Aktion $cmd: $err");
            $c->render(json => { ok => 0, error => "Interner Fehler: $err" }, status => 500);
        }) if $action_promise;
    };

    get '/raw/configs' => sub { shift->render(data => path($configsfile)->slurp); };

    post '/raw/configs' => sub {
        my $c = shift;
        my $raw = $c->req->body // '';

        eval { decode_json($raw); 1 }
            or return _json_err($c, 400, 'Ungueltiges JSON');

        safe_write_file($configsfile, $raw);

        my $newcfg = decode_json($raw);
        _rebuild_cfgmap_from($newcfg);

        $c->render(json => { ok => 1, reload => 1 });
    };

    post '/raw/configs/reload' => sub {
        my $c = shift;
        my $cfg = eval { decode_json(path($configsfile)->slurp) }
            or return _json_err($c, 500, 'JSON-Fehler');

        _rebuild_cfgmap_from($cfg);
        $c->render(json => { ok => 1, reloaded => 1 });
    };

    del '/raw/configs/:name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return _json_err($c, 400, 'Ungueltiger Name') if _bad_name($name);

        my $cfg = decode_json(path($configsfile)->slurp);
        return $c->render(status => 404, json => { ok => 0 }) unless delete $cfg->{$name};

        safe_write_file($configsfile, encode_json($cfg));
        _rebuild_cfgmap_from($cfg);

        $c->render(json => { ok => 1 });
    };

    get '/health' => sub { shift->render(json => { ok => 1, status => 'ok' }); };

    any '/*whatever' => sub { shift->render(json => { ok => 0, error => '404 Not Found' }, status => 404); };

    app->hook(before_dispatch => sub {
        my $c = shift;
        $c->stash(req_id => sprintf('%x-%x-%04x', int(time() * 1000), $$, rand(0xffff)));
        $c->stash(t0     => steady_time());
        $c->stash(client_ip => _client_ip($c));

        my $origin = $c->req->headers->origin // '*';
        if (%ALLOW_ORIGIN) {
            $c->res->headers->header('Access-Control-Allow-Origin' => ($ALLOW_ORIGIN{$origin} ? $origin : 'null'));
        } else {
            $c->res->headers->header('Access-Control-Allow-Origin' => $origin);
        }
        $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS');
        $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, X-API-Token, Authorization');
        $c->res->headers->header('Access-Control-Max-Age'       => '86400');

        $log->info(sprintf('REQUEST %s', _fmt_req($c)));
        return $c->render(text => '', status => 204) if $c->req->method eq 'OPTIONS';

        if ($allowed_ips && @{$allowed_ips}) {
            my $rip = $c->stash('client_ip') // '';
            unless (Net::CIDR::cidrlookup($rip, @{$allowed_ips})) {
                $log->info(sprintf('REQUEST %s -> 403 Forbidden', _fmt_req($c)));
                return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
            }
        }

        if (defined $api_token && length $api_token) {
            my $hdr    = $c->req->headers->header('X-API-Token') // '';
            my $auth   = $c->req->headers->authorization // '';
            my $bearer = $auth =~ /^Bearer\s+(.+)/i ? $1 : '';
            my $token  = $hdr || $bearer;

            unless ($token && secure_compare($token, $api_token)) {
                $log->info(sprintf('REQUEST %s -> 401 Unauthorized', _fmt_req($c)));
                return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' });
            }
        }
    });

    app->hook(after_dispatch => sub {
        my $c = shift;
        my $t0 = $c->stash('t0') // steady_time();
        my $dt = steady_time() - $t0;
        my $code = $c->res->code // 200;
        $log->info(sprintf('RESPONSE %s status=%d time=%.3fs', _fmt_req($c), $code, $dt));
    });

    _rebuild_cfgmap_from($configs);

    $log->info(sprintf(
        'START version=%s umask=%04o path_guard=%s apply_meta=%d entries=%d',
        $VERSION, _cur_umask(), $path_guard, ($apply_meta_enabled ? 1 : 0), scalar(keys %cfgmap)
    ));

    my $listen_url = "http://$global->{listen}";
    if ($global->{ssl_enable}) {
        $listen_url = "https://$global->{listen}?cert=$global->{ssl_cert_file}&key=$global->{ssl_key_file}";
    }
    app->start('daemon', '-l', $listen_url);
}
