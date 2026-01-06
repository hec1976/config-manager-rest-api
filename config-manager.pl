#!/usr/bin/env perl
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

    our $VERSION    = '1.7.7';
    our $globalfile = "$Bin/global.json";
    our $configsfile = "$Bin/configs.json";

    my $log = Mojo::Log->new(level => 'info');

    my $global  = eval { decode_json(path($globalfile)->slurp) };
    die "global.json ungueltig: $@" if $@ || ref($global) ne 'HASH';

    my $configs = eval { decode_json(path($configsfile)->slurp) };
    die "configs.json ungueltig: $@" if $@ || ref($configs) ne 'HASH';

    my $SYSTEMCTL = (defined $global->{systemctl} && $global->{systemctl} ne '')
        ? $global->{systemctl}
        : '/usr/bin/systemctl';

    my $SYSTEMCTL_FLAGS = exists $ENV{SYSTEMCTL_FLAGS}
        ? $ENV{SYSTEMCTL_FLAGS}
        : ($global->{systemctl_flags} // '');

    my @SYSTEMCTL_BASE = ($SYSTEMCTL);
    if (defined $SYSTEMCTL_FLAGS && length $SYSTEMCTL_FLAGS) {
        my @f = shellwords($SYSTEMCTL_FLAGS);
        push @SYSTEMCTL_BASE, @f if @f;
    }

    # Logging Datei (optional)
    my $logfile = $global->{logfile} // "/var/log/config-manager.log";
    my $logdir  = path($logfile)->dirname;
    if (!-d $logdir) {
        eval { $logdir->make_path; 1 };
        chmod 0755, $logdir->to_string if -d $logdir->to_string;
    }
    if (-d $logdir) {
        $log->path($logfile);
        $log->info("Logging in Datei $logfile aktiviert.");
    } else {
        $log->warn("Konnte Log-Verzeichnis $logdir nicht nutzen. Logging auf STDERR.");
    }

    # Mojolicious secrets
    my $sec = $global->{secret};
    my @secrets = ref($sec) eq 'ARRAY' ? @$sec : ($sec // 'change-this-long-random-secret-please');
    app->secrets(\@secrets);
    if (grep { defined($_) && $_ eq 'change-this-long-random-secret-please' } @secrets) {
        $log->warn('[config-manager] WARNING: Standard-Mojolicious Secret wird verwendet! Bitte in global.json anpassen.');
    }

    # Security / Settings
    my $api_token = (defined $ENV{API_TOKEN} && $ENV{API_TOKEN} ne '')
        ? $ENV{API_TOKEN}
        : $global->{api_token};

    my $allowed_ips = $global->{allowed_ips};
    $allowed_ips = [] unless ref($allowed_ips) eq 'ARRAY';

    my $backupRoot = $global->{backupDir} // "$Bin/backup";
    my $tmpDir     = $global->{tmpDir}    // "$Bin/tmp";

    eval { path($backupRoot)->make_path; 1 } or die "Backup-Verzeichnis $backupRoot fehlt/nicht erstellbar";
    chmod 0750, $backupRoot if -d $backupRoot;

    eval { path($tmpDir)->make_path; 1 } or die "Tmp-Verzeichnis $tmpDir fehlt/nicht erstellbar";
    chmod 0750, $tmpDir if -d $tmpDir;

    my $maxBackups          = $global->{maxBackups} // 10;
    my $path_guard          = lc($ENV{PATH_GUARD} // ($global->{path_guard} // 'off'));
    my $apply_meta_enabled  = $global->{apply_meta} // 0;
    my $auto_create_backups = $global->{auto_create_backups} // 0;

    # Allowed roots canonical
    my @ALLOWED_CANON;
    if (ref($global->{allowed_roots}) eq 'ARRAY') {
        my %seen;
        for my $r (@{$global->{allowed_roots}}) {
            my $rp = path($r)->realpath;
            next unless defined $rp && length $rp;
            $rp =~ s{/*$}{};
            $rp .= '/';
            next if $seen{$rp}++;
            push @ALLOWED_CANON, $rp;
        }
    }
    $log->info(@ALLOWED_CANON ? ('ALLOWED_ROOTS=' . join(',', @ALLOWED_CANON)) : 'ALLOWED_ROOTS=(leer)');

    my %TRUSTED = map { $_ => 1 } (ref($global->{trusted_proxies}) eq 'ARRAY' ? @{$global->{trusted_proxies}} : ());
    my %ALLOW_ORIGIN = map { $_ => 1 } (ref($global->{allow_origins}) eq 'ARRAY' ? @{$global->{allow_origins}} : ());

    # ---------------- helpers ----------------

    my $bad_name = sub {
        my ($s) = @_;
        return 1 if !defined $s || $s =~ m{[/\\]};  # Blockiert Schrägstriche
        return 1 if $s =~ m{\.\.} || $s =~ m{^\.};  # Blockiert ".." und Dateinamen, die mit "." beginnen
        return 1 if $s =~ m{[^\w\-\.\_]};           # Erlaubt nur alphanumerische Zeichen, Bindestriche, Punkte und Unterstriche
        return 0;
    };

    my $json_err = sub {
        my ($c, $code, $msg) = @_;
        $code ||= 400;
        return $c->render(status => $code, json => { ok => 0, error => $msg });
    };

    my $canon_dir_of_path = sub {
        my ($p) = @_;
        return undef unless defined $p && length $p;
        my $rp = -e $p ? path($p)->realpath : path($p)->dirname->realpath;
        return undef unless defined $rp && length $rp;
        $rp =~ s{/*$}{};
        $rp .= '/';
        return $rp;
    };

    my $is_allowed_path = sub {
        my ($p) = @_;
        return 0 if -l $p;
        return 1 if $path_guard eq 'off';

        if (!@ALLOWED_CANON) {
            if ($path_guard eq 'audit') { $log->warn("PATH-GUARD audit: keine allowed_roots"); return 1; }
            return 0;
        }

        my $dircanon = $canon_dir_of_path->($p);
        return 0 unless $dircanon;

        for my $root (@ALLOWED_CANON) {
            return 1 if $dircanon eq $root || index($dircanon, $root) == 0;
        }

        if ($path_guard eq 'audit') { $log->warn("PATH-GUARD audit: $p ausserhalb allowed_roots"); return 1; }
        return 0;
    };

    my $mode_str = sub {
        my ($p) = @_;
        return undef unless -e $p;
        return sprintf('%04o', (stat($p))[2] & 07777);
    };

    my $name2uid = sub {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getpwnam($n))[2]);
    };
    my $name2gid = sub {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getgrnam($n))[2]);
    };

    my $apply_meta = sub {
        my ($e, $p) = @_;

        my $auto_wanted = (defined $e->{user} || defined $e->{group} || defined $e->{mode}) ? 1 : 0;
        my $enabled = defined $e->{apply_meta} ? $e->{apply_meta} : ($apply_meta_enabled || $auto_wanted);
        return unless $enabled;

        die "Pfad nicht erlaubt" unless $is_allowed_path->($p);
        die "Symlinks werden abgelehnt" if -l $p;

        my $uid = $name2uid->($e->{user});
        my $gid = $name2gid->($e->{group});

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
        return 1;
    };

    my $backup_dir_for = sub {
        my ($name) = @_;
        my $sub = $name // '';
        $sub =~ s{[^A-Za-z0-9._-]+}{_}g;
        return "$backupRoot/$sub";
    };

    my $ensure_dir = sub {
        my ($dir, $mode) = @_;
        return 1 if -d $dir;
        eval { path($dir)->make_path; 1 } or return;
        chmod($mode, $dir) if -d $dir && defined $mode;
        return -d $dir ? 1 : 0;
    };

    my $ts_compact = sub {
        my $ts = Mojo::Date->new->to_datetime;
        if ($ts =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
            return "$1$2$3\_$4$5$6";
        }
        $ts =~ s/[^0-9]//g;
        return (length($ts) >= 14) ? (substr($ts, 0, 8) . "_" . substr($ts, 8, 6)) : $ts;
    };

    my $write_atomic = sub {
        my ($p, $bytes) = @_;
        my $file = path($p);
        my $tmp  = $file->dirname->child(".tmp_" . $file->basename . ".$$");
        $tmp->spew($bytes);
        $tmp->move_to($file);
        return 'atomic';
    };

    my $safe_write_file = sub {
        my ($p, $bytes) = @_;
        die "Pfad fehlt" unless defined $p && length $p;
    
        my $file = path($p);
        my $dir  = $file->dirname->to_string;
    
        # Wenn wir im Zielverzeichnis kein tmp-File anlegen koennen, dann bringt atomic nichts.
        # Dann direkt plain schreiben (funktioniert fuer existierende Files, und fuer erlaubte Pfade).
        my $dir_writable = (-d $dir && -w $dir) ? 1 : 0;
    
        if (!$dir_writable) {
            path($p)->spew($bytes);
            return 'plain';
        }
    
        my $method = 'atomic';
        my $ok = eval { $write_atomic->($p, $bytes); 1 };
        if (!$ok) {
            $method = 'plain';
            path($p)->spew($bytes);
        }
        return $method;
    };

    my $systemctl_promise = sub {
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

                    return $resolve->($raw_rc >> 8);
                }
            );
        });
    };

    my $capture_cmd_promise = sub {
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
                    for my $fh ($out, $errfh) {
                        while (1) {
                            my $chunk = '';
                            my $r = sysread($fh, $chunk, 8192);
                            last unless $r;
                            $buf .= $chunk;
                        }
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
    };

    my $parse_postmulti_status = sub {
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
    };

    my $client_ip = sub {
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
    };

    my $fmt_req = sub {
        my ($c) = @_;
        return sprintf(
            'req_id=%s ip=%s %s %s',
            ($c->stash('req_id') // ''),
            ($c->stash('client_ip') // ''),
            ($c->req->method // ''),
            ($c->req->url->path->to_string // '')
        );
    };

    # ---------------- cfg map ----------------

    my %cfgmap;

    my $derive_actions = sub {
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
    };

    my $rebuild_cfgmap_from = sub {
        my ($cfg) = @_;
        %cfgmap = ();

        while (my ($name, $entry) = each %{$cfg}) {
            next if !defined $name || $name =~ m{[/\\]} || $name =~ m{\.\.};

            my $actions = $derive_actions->($entry);

            $cfgmap{$name} = {
                %$entry,
                id         => $name,
                service    => $entry->{service}  // $name,
                category   => $entry->{category} // 'uncategorized',
                path       => $entry->{path},
                actions    => $actions,
                backup_dir => $backup_dir_for->($name),
            };
        }
        return 1;
    };

    $rebuild_cfgmap_from->($configs);

    # ---------------- routes ----------------

    get '/' => sub {
        my $c = shift;

        my @routes_list;
        for my $route (@{app->routes->children}) {
            next unless ref $route;
            my $methods = $route->via;
            my $method_str = (ref($methods) eq 'ARRAY' && @$methods) ? join(', ', map { uc } @$methods) : 'ANY';
            push @routes_list, { method => $method_str, path => $route->to_string };
        }
        @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

        $c->render(json => { ok => 1, name => 'config-manager', version => $VERSION, api_endpoints => \@routes_list });
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

        return $json_err->($c, 400, 'Ungueltiger Name') if $bad_name->($name);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannt: $name");
        my $p = $e->{path};

        return $json_err->($c, 400, "Pfad nicht erlaubt") unless $is_allowed_path->($p);
        return $json_err->($c, 404, "Datei fehlt: $p") unless -f $p;

        $c->res->headers->content_type('application/octet-stream');
        $c->render(data => path($p)->slurp);
    };

    post '/config/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return $json_err->($c, 400, 'Ungueltiger Name') if $bad_name->($name);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannt: $name");
        my $p = $e->{path};

        return $json_err->($c, 400, "Pfad nicht erlaubt") unless $is_allowed_path->($p);

        my $content = $c->req->body // '';
        if (($c->req->headers->content_type // '') =~ m{application/json}i) {
            my $j = eval { $c->req->json };
            if (!$@ && ref($j) eq 'HASH' && exists $j->{content}) {
                $content = $j->{content} // '';
            }
        }

        my $bdir = $e->{backup_dir};
        if (!-d $bdir) {
            if ($auto_create_backups) { $ensure_dir->($bdir, 0750); }
            return $json_err->($c, 500, "Backup-Verzeichnis fehlt") unless -d $bdir;
        }

        # backup wenn ziel existiert
        if (-f $p) {
            my $ts = $ts_compact->();
            my $bfile = "$bdir/" . path($p)->basename . ".bak.$ts";
            eval { path($p)->copy_to($bfile); 1 };

            my $base = path($p)->basename;
            my @b = sort { $b cmp $a } grep { defined } glob("$bdir/$base.bak.*");
            if (@b > $maxBackups) { unlink @b[$maxBackups .. $#b]; }
        }

        my $method;
        eval { $method = $safe_write_file->($p, $content); 1 }
            or return $json_err->($c, 500, "Schreibfehler: $@");

        my $meta_wanted = defined $e->{apply_meta}
            ? $e->{apply_meta}
            : ($apply_meta_enabled || defined($e->{user}) || defined($e->{group}) || defined($e->{mode}));

        eval { $apply_meta->($e, $p); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = $mode_str->($p);
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
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false),
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    get '/backups/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return $json_err->($c, 400, 'Ungueltiger Name') if $bad_name->($name);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannte Konfiguration: $name");
        my $bdir = $e->{backup_dir};

        return $c->render(json => { ok => 1, backups => [] }) unless -d $bdir;

        my $base = path($e->{path})->basename;
        my @files = sort { $b cmp $a } grep { defined } glob("$bdir/$base.bak.*");
        @files = map { s{^\Q$bdir\E/}{}r } @files;

        $c->render(json => { ok => 1, backups => \@files });
    };

    get '/backupcontent/*name/*filename' => sub {
        my $c = shift;
        my ($name, $filename) = ($c->stash('name'), $c->stash('filename'));

        return $json_err->($c, 400, 'Ungueltiger Name/Filename') if $bad_name->($name) || $bad_name->($filename);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannte Konfiguration: $name");

        my $bdir = $e->{backup_dir};
        my $base = path($e->{path})->basename;

        return $json_err->($c, 400, 'Ungueltiger Backup-Name')
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $file = "$bdir/$filename";
        return $json_err->($c, 404, 'Backup nicht gefunden') unless -f $file;

        $c->render(json => { ok => 1, content => path($file)->slurp });
    };

    post '/restore/*name/*filename' => sub {
        my $c = shift;
        my ($name, $filename) = ($c->stash('name'), $c->stash('filename'));

        return $json_err->($c, 400, 'Ungueltiger Name/Filename') if $bad_name->($name) || $bad_name->($filename);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannte Konfiguration: $name");

        my $base = path($e->{path})->basename;
        my $bdir = $e->{backup_dir};

        return $json_err->($c, 400, 'Ungueltiger Backup-Name')
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $src  = "$bdir/$filename";
        my $dest = $e->{path};

        return $json_err->($c, 404, 'Backup nicht gefunden') unless -f $src;
        return $json_err->($c, 400, 'Pfad nicht erlaubt') unless $is_allowed_path->($dest);

        path($src)->copy_to($dest) or return $json_err->($c, 500, "Wiederherstellung fehlgeschlagen: $!");

        eval { $apply_meta->($e, $dest); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = $mode_str->($dest);
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
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false),
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    post '/action/*name/*cmd' => sub {
        my $c = shift;
        my ($name, $cmd) = ($c->stash('name'), $c->stash('cmd'));

        return $json_err->($c, 400, 'Ungueltige Anfrage') if $bad_name->($name);

        my $e = $cfgmap{$name} or return $json_err->($c, 404, "Unbekannt");

        my $svc          = $e->{service} // $name;
        my $is_postmulti = ($svc =~ m{^exec:/usr/sbin/postmulti$});
        my $actmap       = $e->{actions};

        return $json_err->($c, 400, 'Aktion nicht erlaubt')
            unless ref($actmap) eq 'HASH' && exists $actmap->{$cmd};

        my @extra = @{$actmap->{$cmd}};
        for (@extra) {
            return $json_err->($c, 400, "Ungueltiges Argument") if $_ !~ /^[A-Za-z0-9._:+@\/=\-,]+$/;
        }

        my $p;

        # Fall 1: postmulti
        if ($is_postmulti) {
            my ($bin) = ($svc =~ m{^exec:(/.+)$});

            $p = $capture_cmd_promise->(30, $bin, @extra)->then(sub {
                my ($res) = @_;

                if ($cmd =~ /^(stop|start|reload|restart)$/) {
                    select(undef, undef, undef, 0.6);
                }

                my @status_args = @{$actmap->{status} // []};
                if (!@status_args) { @status_args = ('-i', $name, '-p', 'status'); }

                return $capture_cmd_promise->(10, $bin, @status_args)->then(sub {
                    my ($status_res) = @_;
                    my $state = $parse_postmulti_status->($status_res->{out}, '', $status_res->{rc});

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
        # Fall 2: daemon-reload
        elsif ($cmd eq 'daemon-reload') {
            $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, 'daemon-reload')->then(sub {
                my $rc = shift;
                $c->render(json => $rc == 0 ? { ok => 1 } : { ok => 0, error => "Rueckgabewert=$rc" });
            });
        }
        # Fall 3: scripts (bash/sh/perl/exec)
        elsif ($svc =~ m{^(bash|sh|perl|exec):(/.+)$}) {
            my ($runner, $script) = ($1, $2);
            return $json_err->($c, 404, "Skript nicht gefunden: $script") unless -f $script;

            if ($runner eq 'exec' && $script =~ m{/systemctl$}) {
                return $json_err->($c, 400, 'Subcommand verboten')
                    if ($extra[0] // '') =~ /^(poweroff|reboot|halt)$/;
            }

            my @argv =
                  $runner eq 'perl' ? ('/usr/bin/perl', $script, @extra)
                : $runner eq 'bash' ? ('/bin/bash', $script, @extra)
                : $runner eq 'sh'   ? ('/bin/sh',   $script, @extra)
                :                    ($script, @extra);

            $p = $capture_cmd_promise->(30, @argv)->then(sub {
                my $res = shift;
                my $rc  = $res->{rc};

                if (($extra[0] // '') eq 'is-active') {
                    $c->render(json => { ok => 1, status => ($rc == 0 ? 'running' : 'stopped'), rc => $rc });
                } else {
                    $c->render(json => { ok => ($rc == 0 ? 1 : 0), rc => $rc, output => $res->{out} });
                }
            });
        }
        # Fall 4: systemctl services
        else {
            if ($cmd eq 'stop_start') {
                $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, 'stop', $svc)
                    ->then(sub { $systemctl_promise->(30, @SYSTEMCTL_BASE, 'start', $svc) });
            }
            elsif ($cmd eq 'restart') {
                $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, 'restart', $svc);
            }
            elsif ($cmd eq 'reload') {
                $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, 'is-active', $svc)->then(sub {
                    my $rc = shift;
                    return $systemctl_promise->(30, @SYSTEMCTL_BASE, 'reload', $svc) if $rc == 0;
                    die "Dienst nicht aktiv\n";
                });
            }
            elsif ($svc eq 'systemctl') {
                return $json_err->($c, 400, 'Verboten') if $cmd =~ /^(poweroff|reboot|halt)$/;
                $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, $cmd, @extra);
            }
            else {
                $p = $systemctl_promise->(30, @SYSTEMCTL_BASE, $cmd, $svc);
            }

            $p->then(sub {
                my $rc = shift;

                if ($cmd =~ /^(stop_start|restart|reload|start|stop)$/) {
                    return $systemctl_promise->(30, @SYSTEMCTL_BASE, 'is-active', $svc)->then(sub {
                        my $active_rc = shift;
                        $c->render(json => {
                            ok     => ($active_rc == 0 || $cmd eq 'stop') ? 1 : 0,
                            action => $cmd,
                            status => ($active_rc == 0 ? 'running' : 'stopped')
                        });
                    });
                }

                $c->render(json => { ok => ($rc == 0 ? 1 : 0), rc => $rc });
            })->catch(sub {
                my $err = shift;
                $c->render(json => { ok => 0, error => "$err" }, status => 500);
            });

            return;
        }

        $p->catch(sub {
            my $err = shift;
            $log->error("Fehler bei Aktion $cmd: $err");
            $c->render(json => { ok => 0, error => "Interner Fehler: $err" }, status => 500);
        }) if $p;
    };

    get '/raw/configs' => sub { shift->render(data => path($configsfile)->slurp); };

    post '/raw/configs' => sub {
        my $c = shift;
        my $raw = $c->req->body // '';

        eval { decode_json($raw); 1 } or return $json_err->($c, 400, 'Ungueltiges JSON');

        $safe_write_file->($configsfile, $raw);

        my $newcfg = decode_json($raw);
        $rebuild_cfgmap_from->($newcfg);

        $c->render(json => { ok => 1, reload => 1 });
    };

    post '/raw/configs/reload' => sub {
        my $c = shift;
        my $cfg = eval { decode_json(path($configsfile)->slurp) } or return $json_err->($c, 500, 'JSON-Fehler');
        $rebuild_cfgmap_from->($cfg);
        $c->render(json => { ok => 1, reloaded => 1 });
    };

    del '/raw/configs/:name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        return $json_err->($c, 400, 'Ungueltiger Name') if $bad_name->($name);

        my $cfg = decode_json(path($configsfile)->slurp);
        return $c->render(status => 404, json => { ok => 0 }) unless delete $cfg->{$name};

        $safe_write_file->($configsfile, encode_json($cfg));
        $rebuild_cfgmap_from->($cfg);

        $c->render(json => { ok => 1 });
    };

    get '/health' => sub { shift->render(json => { ok => 1, status => 'ok' }); };
    any '/*whatever' => sub { shift->render(json => { ok => 0, error => '404 Not Found' }, status => 404); };

    # ---------------- hooks ----------------

    app->hook(before_dispatch => sub {
        my $c = shift;

        $c->stash(req_id => sprintf('%x-%x-%04x', int(time() * 1000), $$, rand(0xffff)));
        $c->stash(t0 => steady_time());
        $c->stash(client_ip => $client_ip->($c));

        my $origin = $c->req->headers->origin // '*';
        if (%ALLOW_ORIGIN) {
            $c->res->headers->header('Access-Control-Allow-Origin' => ($ALLOW_ORIGIN{$origin} ? $origin : 'null'));
        } else {
            $c->res->headers->header('Access-Control-Allow-Origin' => $origin);
        }
        $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS');
        $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, X-API-Token, Authorization');
        $c->res->headers->header('Access-Control-Max-Age'       => '86400');

        $log->info('REQUEST ' . $fmt_req->($c));
        return $c->render(text => '', status => 204) if $c->req->method eq 'OPTIONS';

        if ($allowed_ips && @{$allowed_ips}) {
            my $rip = $c->stash('client_ip') // '';
            unless (Net::CIDR::cidrlookup($rip, @{$allowed_ips})) {
                $log->info('REQUEST ' . $fmt_req->($c) . ' -> 403 Forbidden');
                return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
            }
        }

        if (defined $api_token && length $api_token) {
            my $hdr    = $c->req->headers->header('X-API-Token') // '';
            my $auth   = $c->req->headers->authorization // '';
            my $bearer = $auth =~ /^Bearer\s+(.+)/i ? $1 : '';
            my $token  = $hdr || $bearer;

            unless ($token && secure_compare($token, $api_token)) {
                $log->info('REQUEST ' . $fmt_req->($c) . ' -> 401 Unauthorized');
                return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' });
            }
        }
    });

    app->hook(after_dispatch => sub {
        my $c = shift;
        my $t0 = $c->stash('t0') // steady_time();
        my $dt = steady_time() - $t0;
        my $code = $c->res->code // 200;
        $log->info(sprintf('RESPONSE %s status=%d time=%.3fs', $fmt_req->($c), $code, $dt));
    });

    my $cur_umask = sub { my $o = umask(); umask($o); return $o; };

    $log->info(sprintf(
        'START version=%s umask=%04o path_guard=%s apply_meta=%d entries=%d',
        $VERSION, $cur_umask->(), $path_guard, ($apply_meta_enabled ? 1 : 0), scalar(keys %cfgmap)
    ));

    my $listen_url = "http://$global->{listen}";
    if ($global->{ssl_enable}) {
        $listen_url = "https://$global->{listen}?cert=$global->{ssl_cert_file}&key=$global->{ssl_key_file}";
    }

    app->start('daemon', '-l', $listen_url);
}
