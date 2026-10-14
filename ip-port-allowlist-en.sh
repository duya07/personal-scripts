#!/usr/bin/env bash
# Requires Bash 4.4+, compatible Linux tools and full Perl core modules.
# New/legacy configurations discover non-loopback global addresses with ip -j.
# doctor/menu 9 installs missing dependencies only after explicit confirmation.
set -u
set -o pipefail
umask 077
DIR=${IP_PORT_ALLOWLIST_DIR:-/root}
STATE=$DIR/.ip-port-allowlist.json
JOURNAL=$DIR/.ip-port-allowlist.pending.json
LOCK=$DIR/.ip-port-allowlist.lock
LOGDIR=$DIR/.ip-port-allowlist.logs
LOG_MODE=off LOG_RATE=10 LOG_BURST=5 LOG_PREFIX=''
LOG_CANDIDATE='' LOG_BEFORE='' LOG_SAVE_PENDING=0
AUDIT_ACTION='' AUDIT_DETAIL=''
WORK=''
TRANSACTION=0
RECOVERY_KEEP=0
COLOR=0
AUTO_ADDRESSES=''
[[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} ]] && COLOR=1
UNI=0
case ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} in *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) UNI=1 ;; esac
error() { printf 'Error: %s\n' "$*" >&2; }
die() { error "$*"; exit 2; }
((BASH_VERSINFO[0]>4 || (BASH_VERSINFO[0]==4 && BASH_VERSINFO[1]>=4))) || die 'Bash 4.4 or newer is required; install Bash and run this script with bash'
styled() { if ((COLOR)); then printf '\033[%sm%s\033[0m\n' "$2" "$1"; else printf '%s\n' "$1"; fi; }
data() {
    if [[ -z $AUTO_ADDRESSES ]]; then
        AUTO_ADDRESSES=$(ip -j address show scope global) || { error 'Cannot detect local target addresses; check ip -j address show scope global'; return 2; }
    fi
    IP_PORT_ALLOWLIST_AUTO_TARGETS=$AUTO_ADDRESSES perl - "$@" <<'PERL'
use strict;
use warnings;
use utf8;
use JSON::PP;
use Socket qw(AF_INET AF_INET6 inet_pton);
use Encode qw(decode);
use B ();
binmode STDOUT, ':encoding(UTF-8)';
binmode STDERR, ':encoding(UTF-8)';
my $json=JSON::PP->new->canonical->ascii;
sub fail { die "$_[0]\n" }
sub text { my($p)=@_; open my $h,'<:encoding(UTF-8)',$p or fail("Cannot read $p: $!"); local $/; my $s=<$h>; close $h or fail("Cannot close $p: $!"); defined($s)?$s:'' }
sub readjson { $json->decode(text($_[0])) }
sub emit { print $json->pretty->encode($_[0]); $json->pretty(0) }
sub str { !ref($_[0]) && defined($_[0]) && (B::svref_2object(\$_[0])->FLAGS & B::SVp_POK()) }
sub obj { ref($_[0]) eq 'HASH' }
sub arr { ref($_[0]) eq 'ARRAY' }
sub keysare { my($h,@k)=@_; obj($h) && join(',',sort keys %$h) eq join(',',sort @k) }
sub parts { grep {length} split /[\s,]+/, $_[0] }
sub ipv4bytes { my($s)=@_; my @a=split /\./,$s,-1; fail("Invalid IPv4 address: $s") unless @a==4 && !grep {!/\A(?:0|[1-9][0-9]{0,2})\z/ || $_>255} @a; pack('C4',@a) }
sub ipnet {
    my($s)=@_; fail('IP must be a string') unless str($s);
    my @v=split m{/},$s,-1; fail("Invalid IP or network: $s") if @v>2 || $v[0]=~/[%\s]/;
    my($addr,$pre)=@v; my $f=index($addr,':')>=0?6:4; my $bits=$f==4?32:128; my $packed;
    if($f==4){$packed=ipv4bytes($addr)}else{if($addr=~/([^:]+\.[^:]+)\z/){ipv4bytes($1)} $packed=inet_pton(AF_INET6,$addr); fail("Invalid IPv6 address: $s") unless defined $packed}
    if(!defined $pre){$pre=$bits}
    elsif($f==4 && $pre=~/\./){my $mask=unpack('B32',ipv4bytes($pre)); $mask=~tr/01/10/ if $mask=~/\A0/ && $mask ne '0'x32; fail("Invalid subnet mask: $s") unless $mask=~/\A(1*)(0*)\z/; $pre=length($1)}
    else{fail("Invalid prefix length: $s") unless $pre=~/\A[0-9]+\z/ && $pre<=$bits; $pre=0+$pre}
    my $binary=unpack('B*',$packed); substr($binary,$pre)='0'x($bits-$pre); $packed=pack('B*',$binary); my $n;
    if($f==4){$n=join('.',unpack('C4',$packed))}
    else{my @w=unpack('n8',$packed); my($best,$len)=(-1,0);for(my $i=0;$i<8;){if($w[$i]){$i++;next}my $j=$i;$j++ while $j<8&&!$w[$j];if($j-$i>$len&&$j-$i>=2){($best,$len)=($i,$j-$i)}$i=$j}my @h=map {sprintf '%x',$_} @w;if($best<0){$n=join(':',@h)}else{my $l=$best?join(':',@h[0..$best-1]):'';my $r=$best+$len<8?join(':',@h[$best+$len..7]):'';$n=$l.'::'.$r}}
    return ("$n/$pre","$f",$pre,$packed);
}
sub ips {my(%seen,@out);for(parts($_[0])){my($n)=ipnet($_);push @out,$n unless $seen{$n}++}fail('IP must not be empty') unless @out;\@out}
sub ports {my %p;for(parts($_[0])){fail("Invalid port: $_ (valid range 1-65535)") unless /\A[0-9]+\z/ && $_>=1 && $_<=65535;$p{0+$_}=1}fail('Ports must not be empty') unless %p;[sort {$a<=>$b} keys %p]}
sub protos {my $s=lc $_[0];$s=~tr{/}{,};$s='tcp,udp' if $s eq 'both';my %p=map {$_=>1} parts($s);fail('Protocol must be tcp, udp or both') unless %p&&!grep {$_ ne 'tcp'&&$_ ne 'udp'} keys %p;[grep {$p{$_}} qw(tcp udp)]}
sub families {my($s,$i)=@_;my %available=map {(ipnet($_))[1]=>1} @{$i||[]};my %f=$s eq 'auto'?%available:$s eq 'both'?('4'=>1,'6'=>1):($s=>1);fail('Invalid address family') unless %f&&!grep {$_ ne '4'&&$_ ne '6'} keys %f;fail('Source IP families must match the selected address family; choosing IPv4 + IPv6 requires both IPv4 and IPv6 sources') if defined($i)&&join(',',sort keys %f) ne join(',',sort keys %available);[sort keys %f]}
sub empty {return {version=>3,targets=>{'4'=>[],'6'=>[]},rules=>{'4'=>{tcp=>{},udp=>{}},'6'=>{tcp=>{},udp=>{}}}}}
sub autotargets {
    my $a=$json->decode($ENV{IP_PORT_ALLOWLIST_AUTO_TARGETS}//'[]');fail('Invalid local address JSON') unless arr($a);
    my $t={'4'=>[],'6'=>[]};my %seen;
    for my $nic(@$a){fail('Invalid local interface JSON') unless obj($nic);next if ($nic->{ifname}//'') eq 'lo';my $info=$nic->{addr_info}//[];fail('Invalid local address list') unless arr($info);
        for my $v(@$info){fail('Invalid local address entry') unless obj($v);next unless ($v->{scope}//'') eq 'global'&&(($v->{family}//'') eq 'inet'||($v->{family}//'') eq 'inet6');my $flags=$v->{flags}//[];fail('Invalid local address flags') unless arr($flags);next if $v->{tentative}||$v->{dadfailed}||grep {$_ eq 'tentative'||$_ eq 'dadfailed'} @$flags;my($n,$f,$p)=ipnet($v->{local});fail('Local address family mismatch') unless $f eq ($v->{family} eq 'inet'?'4':'6');fail('A local address must be a single host address') unless $p==($f eq '4'?32:128);push @{$t->{$f}},$n unless $seen{$n}++}
    }return $t;
}
sub targetguard {my($s)=@_;for my $f(qw(4 6)){fail("IPv$f already has port rules but no target host address; configure one first with menu 8 or targets --family $f --ips HOST") if !@{$s->{targets}{$f}}&&(keys %{$s->{rules}{$f}{tcp}}||keys %{$s->{rules}{$f}{udp}})}}
sub targetlist {my($iv,$f)=@_;fail('Target host address family must be 4 or 6') unless $f eq '4'||$f eq '6';my $i=ips($iv);for(@$i){my(undef,$fam,$p)=ipnet($_);fail('A target must be a single host address of the matching family (IPv4 /32, IPv6 /128)') unless $fam eq $f&&$p==($f eq '4'?32:128)}$i}
sub normalize {
    my($raw)=@_;fail('The configuration file must be a JSON object') unless obj($raw);my $s=empty();
    if(!exists $raw->{version}){$raw={version=>2,targets=>autotargets(),rules=>{'4'=>{tcp=>$raw,udp=>{}},'6'=>{tcp=>{},udp=>{}}}}}
    fail('Unsupported configuration file format') unless keysare($raw,qw(version targets rules))&&!ref($raw->{version})&&!str($raw->{version})&&($raw->{version}==2||$raw->{version}==3);
    for(qw(targets rules)){fail("Invalid configuration field: $_") unless keysare($raw->{$_},'4','6')}
    for my $f(qw(4 6)){my $t=$raw->{targets}{$f};fail('Targets must be an array of strings') unless arr($t)&&!grep {!str($_)} @$t;$s->{targets}{$f}=@$t?targetlist(join(',',@$t),$f):[];my $r=$raw->{rules}{$f};fail('Invalid protocol table in the configuration') unless keysare($r,qw(tcp udp));for my $pr(qw(tcp udp)){fail('Invalid port table in the configuration') unless obj($r->{$pr});for my $n(keys %{$r->{$pr}}){fail('Invalid port in the configuration') unless $n=~/\A[1-9][0-9]*\z/&&$n<=65535;my $i=$r->{$pr}{$n};fail('Sources must be an array of strings') unless arr($i)&&!grep {!str($_)} @$i;fail('An empty source array requires configuration version 3') if !@$i&&$raw->{version}!=3;my $src=@$i?ips(join(',',@$i)):[];fail('Sources do not match the address family') if grep {(ipnet($_))[1] ne $f} @$src;$s->{rules}{$f}{$pr}{$n}=$src}}}targetguard($s);return $s;
}
sub load {if(-e $_[0]){return normalize(readjson($_[0]))}my $s=empty();$s->{targets}=autotargets();return $s}
sub same {$json->encode($_[0]) eq $json->encode($_[1])}
sub changes {
    my($before,$after)=@_;my @out;
    for my $f(qw(4 6)){for my $pr(qw(tcp udp)){my($x,$y)=($before->{rules}{$f}{$pr},$after->{rules}{$f}{$pr});my %u=map {$_=>1}(keys %$x,keys %$y);for my $n(sort {$a<=>$b} keys %u){next if exists($x->{$n})==exists($y->{$n})&&same([sort @{$x->{$n}||[]}],[sort @{$y->{$n}||[]}]);push @out,[$f,$pr,$n,$x->{$n},$y->{$n}]}}}return \@out;
}
sub transform {
    my($state,$cmd,$iv,$pv,$pr,$fv,$ni,$np)=@_;my $s=$json->decode($json->encode($state));
    if($cmd eq 'clear'){$s->{rules}=empty()->{rules};return $s}
    return $s if $cmd eq 'restore';
    if($cmd eq 'targets'){$s->{targets}{$fv}=targetlist($iv,$fv);return $s}
    my $i=length($iv)?ips($iv):undef;my $ports=ports($pv);my $pro=length($pr)?protos($pr):undef;
    if($cmd eq 'edit'){
        fail('Specify at least one of --proto, --new-ips or --new-ports') unless defined($pro)||length($ni)||length($np);
        my $newi=length($ni)?ips($ni):undef;my $newp=length($np)?ports($np):undef;
        my %selected=map {$_=>1} @$i;my %ports=map {$_=>1} @$ports;my(@m,%mi,%mp,%mf);
        for my $f(qw(4 6)){for my $p(qw(tcp udp)){for my $n(keys %{$state->{rules}{$f}{$p}}){my @chosen=grep {$selected{$_}} @{$state->{rules}{$f}{$p}{$n}};next unless $ports{$n}&&@chosen;push @m,[$f,$p,$n,\@chosen];$mi{$_}=1 for @chosen;$mp{$n}=1;$mf{$f}=1}}}
        fail('No matching source/port association found') unless @m;
        fail('Some of the selected sources are not associated with these ports') unless join(',',sort keys %mi) eq join(',',sort @$i);
        fail('Some of the selected ports are not associated with these sources') unless join(',',sort keys %mp) eq join(',',sort @$ports);
        if(defined $newi){my %nf=map {(ipnet($_))[1]=>1} @$newi;fail('New sources must use the same address family as the selected rules') unless join(',',sort keys %nf) eq join(',',sort keys %mf)}
        for(@m){my($f,$p,$n,$chosen)=@$_;my %c=map {$_=>1} @$chosen;my @left=grep {!$c{$_}} @{$s->{rules}{$f}{$p}{$n}};if(@left){$s->{rules}{$f}{$p}{$n}=\@left}else{delete $s->{rules}{$f}{$p}{$n}}}
        for(@m){my($f,$p,$n,$chosen)=@$_;my @src=defined($newi)?grep {(ipnet($_))[1] eq $f} @$newi:@$chosen;for my $dp(@{$pro||[$p]}){for my $dn(@{$newp||[$n]}){my $r=$s->{rules}{$f}{$dp};fail("IPv$f $dn/$dp currently denies all sources; rewrite it explicitly with Set / Replace allowlist") if exists($r->{$dn})&&!@{$r->{$dn}};$r->{$dn}||=[];my %seen=map {$_=>1} @{$r->{$dn}};for my $src(@src){push @{$r->{$dn}},$src unless $seen{$src}++}}}}
        return @{changes($state,$s)}?normalize($s):$state;
    }
    my $f=families($fv,$i);for my $fam(@$f){for my $p(@$pro){for my $n(@$ports){if($cmd eq 'remove'){delete $s->{rules}{$fam}{$p}{$n}}elsif($cmd eq 'block'){$s->{rules}{$fam}{$p}{$n}=[]}else{$s->{rules}{$fam}{$p}{$n}=[grep {(ipnet($_))[1] eq $fam} @$i]}}}}return $s;
}
sub guard {
    my($s)=@_;my @c=split /\s+/,$ENV{SSH_CONNECTION}||'';return unless @c==4;
    fail('Invalid SSH_CONNECTION') if $c[0]=~m{/}||$c[2]=~m{/}||$c[3]!~/\A[0-9]+\z/||$c[3]<1||$c[3]>65535;
    my(undef,$cf,undef,$client)=ipnet($c[0]);my(undef,$sf,undef,$server)=ipnet($c[2]);return unless grep {(ipnet($_))[3] eq $server} @{$s->{targets}{$sf}};
    my $r=$s->{rules}{$sf}{tcp};my $n=''.(0+$c[3]);return unless exists $r->{$n};my $ok=0;
    for(@{$r->{$n}}){my(undef,$f,$pre,$bytes)=ipnet($_);next unless $cf eq $f;my $b=unpack('B*',$client);substr($b,$pre)='0'x(length($b)-$pre);$ok=1 if pack('B*',$b) eq $bytes}
    fail("This configuration would block the source of the current SSH connection $c[0] (TCP $n); add it to the allowlist") unless $ok;
}
sub rows {
    my($s)=@_;my %g;for my $f(qw(4 6)){for my $p(qw(tcp udp)){for my $n(keys %{$s->{rules}{$f}{$p}}){$g{$_}{$n}{$p}=1 for @{$s->{rules}{$f}{$p}{$n}}}}}
    my @src=sort {my(undef,$af,$ap,$ab)=ipnet($a);my(undef,$bf,$bp,$bb)=ipnet($b);$af<=>$bf||$ab cmp $bb||$ap<=>$bp} keys %g;
    my @out;for my $src(@src){my @p;for my $n(sort {$a<=>$b} keys %{$g{$src}}){push @p,$n.'('.join('/',map {uc} grep {$g{$src}{$n}{$_}} qw(tcp udp)).')'}push @out,[$src,join(', ',@p)]}return \@out;
}
sub printstate {
    my($s)=@_;print "\n  Saved port policy\n";my $rows=rows($s);my $any=0;
    for my $f(qw(4 6)){
        my $targets=$s->{targets}{$f};print "\n  IPv$f target: ",@$targets?join(', ',@$targets):'not configured (no port restrictions possible for this family)',"\n";
        my @familyrows=grep {(ipnet($_->[0]))[1] eq $f} @$rows;
        print "  IPv$f allowlist\n" if @familyrows;
        for(@familyrows){print "  [IPv$f] ",$_->[0],' → ',$_->[1],"\n"}$any=1 if @familyrows;
        my %p;for my $pr(qw(tcp udp)){for my $n(keys %{$s->{rules}{$f}{$pr}}){$p{$n}{$pr}=1 unless @{$s->{rules}{$f}{$pr}{$n}}}}
        if(%p){$any=1;print "  Deny all sources · IPv$f → ",join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$p{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %p),"\n"}
        print "  IPv$f has no managed port restrictions\n" unless @familyrows||%p||!@$targets;
    }
    print $any?"\n  Allowlisted ports accept only the listed sources; other ports keep their previous policy.\n":"\n  No managed port restrictions\n";
}
sub summary {
    my($s)=@_;print "\n  Current overview\n";
    for my $f(qw(4 6)){
        my $t=$s->{targets}{$f};
        if(!@$t){print "  IPv$f target: not configured\n";next}
        my %p;for my $pr(qw(tcp udp)){$p{$_}{$pr}=1 for keys %{$s->{rules}{$f}{$pr}}}
        print "  IPv$f target: ",join(', ',@$t)," · managed ports: ",(%p?join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$p{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %p):'none'),"\n";
    }
    print "  Choose 1 to view the full allowlist details.\n";
}
sub chain {defined($_[0])&&!ref($_[0])&&$_[0]=~/\AIPW_[0-9a-f]{10}\z/}
sub tokens {my($a)=@_;fail('Invalid rule parameters') unless arr($a)&&!grep {!str($_)||/[\x00\r\n]/} @$a}
sub snapshot_valid {
    my($s)=@_;fail('Invalid recovery snapshot') unless keysare($s,qw(chains rules hooks))&&arr($s->{chains})&&arr($s->{rules})&&arr($s->{hooks});my %c;for(@{$s->{chains}}){fail('Invalid chain in the recovery snapshot') unless chain($_)&&!$c{$_}++}
    for(@{$s->{rules}}){tokens($_);fail('Invalid rule in the recovery snapshot') unless @$_>=2&&$_->[0] eq '-A'&&$c{$_->[1]}}
    my $last=0;for(@{$s->{hooks}}){fail('Invalid hook in the recovery snapshot') unless keysare($_,qw(position args));my $n=$_->{position};fail('Invalid position in the recovery snapshot') unless defined($n)&&!ref($n)&&$n=~/\A[1-9][0-9]*\z/&&$n>$last;$last=$n;tokens($_->{args});my @a=@{$_->{args}};my $refs=0;for(my $i=0;$i<@a-1;$i++){if($a[$i] eq '-j'||$a[$i] eq '-g'){fail('Invalid target in the recovery snapshot') unless $c{$a[$i+1]};$refs++}}fail('A recovery hook must have exactly one target') unless $refs==1}return $s;
}
sub logging_settings_valid {
    my($s)=@_;
    fail('Invalid logging settings in recovery journal') unless keysare($s,qw(version operations connections max_mib keep retention_days rate burst auto_rotate));
    my %range=(version=>[1,1],max_mib=>[1,100],keep=>[1,20],retention_days=>[0,365],rate=>[1,100],burst=>[1,100]);
    for my $k(keys %range){my $v=$s->{$k};fail('Invalid logging settings in recovery journal') unless defined($v)&&!ref($v)&&!str($v)&&$v=~/\A[0-9]+\z/&&$v>=$range{$k}[0]&&$v<=$range{$k}[1]}
    for my $k(qw(operations connections auto_rotate)){my $v=$s->{$k};my $rx=$k eq 'connections'?qr/\A(?:off|deny|all)\z/:qr/\A(?:off|on)\z/;fail('Invalid logging settings in recovery journal') unless str($v)&&$v=~$rx}
    return $s;
}
sub journal {
    my $j=readjson($_[0]);fail('Invalid recovery journal') unless (keysare($j,qw(snapshots state))||keysare($j,qw(snapshots state logging)))&&obj($j->{snapshots})&&!grep {$_ ne '4'&&$_ ne '6'} keys %{$j->{snapshots}};
    snapshot_valid($_) for values %{$j->{snapshots}};
    fail('Invalid recovery state') if defined($j->{state})&&!str($j->{state});normalize($json->decode($j->{state})) if defined $j->{state};
    if(exists($j->{logging})&&defined($j->{logging})){fail('Invalid logging settings in recovery journal') unless str($j->{logging});logging_settings_valid($json->decode($j->{logging}))}
    return $j;
}
sub flagval { my($a,$n)=@_; for(my $i=0;$i<@$a-1;$i++){return $a->[$i+1] if $a->[$i] eq $n} return undef }
sub repair_fail { fail('Live rules cannot be reconstructed without changing their meaning; keep the backup and review them manually') }
sub rebuild_fields {
    my($a,$mode)=@_;my(%fields,%modules);my $lo=0;
    my %keys=$mode eq 'hook'?('-p'=>'proto','-d'=>'dest','-j'=>'jump','-g'=>'jump'):('-p'=>'proto','--dport'=>'port','-s'=>'src','-j'=>'jump');
    for(my $i=0;$i<@$a;$i++){
        my $key=$a->[$i];
        if($key eq '!'){
            repair_fail() unless $mode eq 'hook'&&!$lo&&$i+2<@$a&&$a->[$i+1] eq '-i'&&$a->[$i+2] eq 'lo';
            $lo=1;$i+=2;next;
        }
        repair_fail() unless $i+1<@$a;
        my $value=$a->[++$i];
        if($key eq '-m'){
            repair_fail() unless ($value eq 'comment'||$value eq 'tcp'||$value eq 'udp')&&!$modules{$value};
            $modules{$value}=1;next;
        }
        if($key eq '--comment'){
            repair_fail() unless $modules{comment}&&!exists $fields{comment};$fields{comment}=$value;next;
        }
        repair_fail() unless exists($keys{$key})&&!exists($fields{$keys{$key}});
        $fields{$keys{$key}}=$value;
    }
    repair_fail() if $mode eq 'hook'&&!$lo;
    repair_fail() if ($modules{comment}||0)!=(exists($fields{comment})?1:0);
    for my $pr(qw(tcp udp)){repair_fail() if $modules{$pr}&&(!defined($fields{proto})||$fields{proto} ne $pr)}
    return \%fields;
}
sub rebuild_log {
    my($a)=@_;return 0 unless grep {$_ eq 'LOG'} @$a;
    my(@verdict,%extra);my $limit=0;
    for(my $i=0;$i<@$a;$i++){
        my $k=$a->[$i];repair_fail() unless $i+1<@$a;my $v=$a->[++$i];
        if($k eq '-m'&&$v eq 'limit'){repair_fail() if $limit++;next}
        if($k=~/\A(?:--limit|--limit-burst|--log-prefix|--log-level)\z/){repair_fail() if exists $extra{$k};$extra{$k}=$v;next}
        push @verdict,$k,$v;
    }
    $extra{'--limit-burst'}=5 unless exists $extra{'--limit-burst'};
    repair_fail() unless $limit&&keys(%extra)==4;
    repair_fail() unless $extra{'--limit'}=~/\A([1-9][0-9]*)\/(?:min|minute)\z/&&$1<=100;
    repair_fail() unless $extra{'--limit-burst'}=~/\A[1-9][0-9]*\z/&&$extra{'--limit-burst'}<=100;
    repair_fail() unless $extra{'--log-level'} eq '6';
    repair_fail() unless $extra{'--log-prefix'}=~/\AIPW_[0-9a-f]{10}_([AD]) \z/;
    my $tag=$1;my $fields=rebuild_fields(\@verdict,'rule');
    repair_fail() unless ($fields->{jump}//'') eq 'LOG';
    repair_fail() unless defined($fields->{proto})&&($fields->{proto} eq 'tcp'||$fields->{proto} eq 'udp')&&defined($fields->{port})&&$fields->{port}=~/\A[1-9][0-9]*\z/&&$fields->{port}<=65535;
    repair_fail() unless $tag eq 'A'?defined($fields->{src}):!defined($fields->{src});
    ipnet($fields->{src}) if defined $fields->{src};
    return 1;
}
sub unsquote { my($s)=@_; $s=~s/"(?:\\.|[^"\\])*"//g; $s=~s/'(?:\\.|[^'\\])*'//g; return $s }
sub saverules {
    my($p)=@_; my(@rules,@chains); my $table=0;
    return ([],[]) unless defined($p)&&length($p)&&-e $p;
    for my $l(split /\n/,text($p)){
        next if $l eq ''||$l=~/^#/;
        if($l eq '*raw'){$table=1;next}
        if($l eq 'COMMIT'){$table=0;next}
        fail('Invalid firewall output format') unless $table;
        if($l=~/^:(\S+) (\S+) \[([0-9]+):([0-9]+)\]\z/){my($n,$pol,$pk,$by)=($1,$2,$3,$4);push @chains,{name=>$n,policy=>$pol,packets=>0+$pk,bytes=>0+$by} if $n=~/\AIPW_[0-9a-f]{10}\z/;next}
        fail('Invalid firewall output format') unless $l=~/^(?:\[([0-9]+):([0-9]+)\] )?-A (\S+)(?:\s(.*))?\z/;
        my($pk,$by,$chain,$rest)=($1//0,$2//0,$3,$4//'');
        my @f=split /\s+/,unsquote($rest);
        push @rules,{chain=>$chain,packets=>0+$pk,bytes=>0+$by,rule=>length($rest)?"-A $chain $rest":"-A $chain",proto=>flagval(\@f,'-p'),dport=>flagval(\@f,'--dport'),source=>flagval(\@f,'-s'),dest=>flagval(\@f,'-d'),target=>flagval(\@f,'-j')//flagval(\@f,'-g')};
    }
    (\@rules,\@chains);
}
# Terminal panels follow the reference Python display-width and wrapping rules.
my($ui_width,$ui_color,$ui_uni)=(96,0,1);
sub ui_text {my $s=$_[0];if(!$ui_uni){$s=~s/→/->/g;$s=~s/·/-/g}return $s}
sub ui_width {
    my $s=$_[0];$s=~s/\e\[[0-9;]*m//g;my $n=0;
    for(split //,$s){next if /\p{Mn}|\p{Me}/;$n+=/\p{East_Asian_Width=Wide}|\p{East_Asian_Width=Fullwidth}/?2:1}return $n;
}
sub ui_style {my($s,$tone)=@_;return $ui_color&&length($tone// '')?"\e[${tone}m$s\e[0m":$s}
sub ui_wrap {
    my($text,$width,$indent)=@_;$text=ui_text($text);$indent//='';my @lines;
    for my $part(split /\n/,$text,-1){
        my $current=$part;
        while(ui_width($current)>$width){
            my($used,$end)=(0,0);for my $char(split //,$current){$used+=ui_width($char);last if $used>$width;$end++}
            last unless $end;
            my $prefix=substr($current,0,$end);my $boundary=rindex($prefix,', ');my $space=rindex($prefix,' ');$boundary=$space if $space>$boundary;
            $end=$boundary+1 if $boundary>length($indent);
            my $line=substr($current,0,$end);$line=~s/\s+\z//;push @lines,$line;
            $current=substr($current,$end);$current=~s/\A\s+//;$current=$indent.$current;
        }
        push @lines,$current;
    }return @lines;
}
sub ui_edge {
    my($left,$right)=@_;my $line=$ui_uni?'─':'-';print ui_style('  '.$left.($line x ($ui_width-2)).$right,'36'),"\n";
}
sub ui_line {
    my($s,$tone)=@_;my $border=$ui_uni?'│':'|';my $padding=$ui_width-6-ui_width($s);$padding=0 if $padding<0;
    print ui_style('  '.$border,'36'),'  ',ui_style($s.(' ' x $padding),$tone),'  ',ui_style($border,'36'),"\n";
}
sub ui_lines {my($s,$tone,$indent)=@_;ui_line($_,$tone) for ui_wrap($s,$ui_width-6,$indent)}
sub ui_section {
    my $label=($ui_uni?'─ ':'- ').ui_text($_[0]).' ';my $line=$ui_uni?'─':'-';my $remaining=$ui_width-2-ui_width($label);
    if($remaining<0){ui_edge($ui_uni?'├':'+',$ui_uni?'┤':'+');ui_lines($_[0],'1;36');return}
    print ui_style('  '.($ui_uni?'├':'+').$label.($line x $remaining).($ui_uni?'┤':'+'),'36'),"\n";
}
sub render_panel {
    my($kind,$value,$width,$color,$uni,$note,$status,$broken)=@_;
    fail('Invalid panel parameters') unless defined($width)&&$width=~/\A[0-9]+\z/&&$width>=36&&$width<=108;
    ($ui_width,$ui_color,$ui_uni)=(0+$width,$color?1:0,$uni?1:0);$note//='';$status//='';
    print "\n";ui_edge($ui_uni?'╭':'+',$ui_uni?'╮':'+');
    if($kind eq 'title'){
        ui_lines($value,'1;36');ui_lines($note,'2') if length $note;
        ui_edge($ui_uni?'╰':'+',$ui_uni?'╯':'+');print "\n";return;
    }
    fail('Invalid panel type') unless $kind eq 'menu';
    ui_lines('IP / Port allowlist manager','1;36');ui_lines('IPv4 / IPv6  ·  TCP / UDP','2');
    ui_lines($note,'33') if length $note;
    ui_section('Current rules · saved');
    if(length $status){ui_lines('Rule read failed: '.$status,'31')}
    else{
        my $state=load($value);
        for my $f(qw(4 6)){ui_lines("IPv$f  ".(@{$state->{targets}{$f}}?join(', ',@{$state->{targets}{$f}}):'not configured'),'2')}
        my @entries=map {['Allow  '.$_->[0].' → ',$_->[1],'32']} @{rows($state)};
        for my $f(qw(4 6)){
            my %ports;for my $pr(qw(tcp udp)){for my $n(keys %{$state->{rules}{$f}{$pr}}){$ports{$n}{$pr}=1 unless @{$state->{rules}{$f}{$pr}{$n}}}}
            my $ports=join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$ports{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %ports);
            push @entries,["Block  IPv$f / all sources → ",$ports,'1;31'] if length $ports;
        }
        ui_lines('No allowlist or blocked-port rules','33') unless @entries;
        for my $entry(@entries){
            my $prefix=ui_text($entry->[0]);my $indent=ui_width($prefix);my $limit=$ui_width-24;$limit=2 if $limit<2;$indent=$limit if $indent>$limit;
            ui_lines($prefix.$entry->[1],$entry->[2],' ' x $indent);
        }
    }
    ui_section('Actions');
    my @options=([1,'View allowlist / block rules','1;32'],[2,'Set / Replace allowlist','32'],[3,'Edit existing allowlist','36'],[4,'Remove restrictions from given ports','33'],[5,'Clear all restrictions','31'],[6,'View live firewall rules','36'],[7,'Block ports (deny all sources)','1;31'],[8,'Set target host addresses','36'],[9,'Check / install dependencies','36'],[10,'Logs','36'],[11,'Log rotation and clear settings','36']);
    push @options,['R','Repair the corrupt state file','1;31'] if $broken;
    push @options,[0,'Quit','2'];
    my @labels=map {($_->[0] eq '10' || $_->[0] eq '11' ? $_->[0].' '.$_->[1] : $_->[0].'  '.$_->[1])} @options;my $column=int(($ui_width-10)/2);my $longest=0;
    for(@labels){my $n=ui_width($_);$longest=$n if $n>$longest}
    if($column>=$longest){
        for(my $i=0;$i<@options;$i+=2){
            my $left=ui_style($labels[$i],$options[$i][2]);
            if($i+1<@options){$left.=' ' x ($column-ui_width($labels[$i])+4);$left.=ui_style($labels[$i+1],$options[$i+1][2])}
            ui_line($left,'');
        }
    }else{for(my $i=0;$i<@options;$i++){ui_lines($labels[$i],$options[$i][2])}}
    ui_section('Enter a number · Ctrl+C to quit');ui_edge($ui_uni?'╰':'+',$ui_uni?'╯':'+');print "\n";
}
my $ok=eval {
    my $cmd=shift @ARGV;@ARGV=map {decode('UTF-8',$_)} @ARGV;
    if($cmd eq 'args'){emit([@ARGV])}
    elsif($cmd eq 'panel'){render_panel(@ARGV)}
    elsif($cmd eq 'load'){emit(load($ARGV[0]))}
    elsif($cmd eq 'validate'){my($iv,$pv,$pr,$fv)=@ARGV;my $i=ips($iv);emit({ips=>$i,ports=>ports($pv),protocols=>protos($pr),families=>families($fv,$i)})}
    elsif($cmd eq 'transform'){my $p=shift @ARGV;emit(normalize(transform(load($p),@ARGV)))}
    elsif($cmd eq 'guard'){guard(load($ARGV[0]))}
    elsif($cmd eq 'token'){print $json->encode(load($ARGV[0]))}
    elsif($cmd eq 'show'){printstate(load($ARGV[0]))}
    elsif($cmd eq 'summary'){summary(load($ARGV[0]))}
    elsif($cmd eq 'check-ips'){ips($ARGV[0])}
    elsif($cmd eq 'check-ports'){ports($ARGV[0])}
    elsif($cmd eq 'check-hosts'){targetlist($ARGV[1],$ARGV[0])}
    elsif($cmd eq 'check-sources'){my $s=load($ARGV[0]);my %f;for(@{ips($ARGV[1])}){$f{(ipnet($_))[1]}=1}for my $f(sort keys %f){fail("IPv$f sources require an IPv$f target host address first; configure one with menu 8") unless @{$s->{targets}{$f}}}}
    elsif($cmd eq 'families'){my $s=load($ARGV[0]);print "$_\n" for grep {@{$s->{targets}{$_}}} qw(4 6)}
    elsif($cmd eq 'rows'){for(@{rows(load($ARGV[0]))}){print join("\t",@$_),"\n"}}
    elsif($cmd eq 'available') {
        my($p,$iv)=@ARGV;
        my %i=map {$_=>1} @{ips($iv)};
        my $s=load($p); my %ports;
        for my $f(qw(4 6)) {
            for my $pr(qw(tcp udp)) {
                for my $n(keys %{$s->{rules}{$f}{$pr}}) {
                    $ports{$n}{$pr}=1 if grep {$i{$_}} @{$s->{rules}{$f}{$pr}{$n}};
                }
            }
        }
        for my $n(sort {$a<=>$b} keys %ports) {
            print $n,"\t",join('/',map {uc} grep {$ports{$n}{$_}} qw(tcp udp)),"\n";
        }
    }
    elsif($cmd eq 'filter-sources'){my($p,$iv,$pv)=@ARGV;my $s=load($p);my %ports=map {$_=>1} @{ports($pv)};my %i;for my $f(qw(4 6)){for my $pr(qw(tcp udp)){for my $n(keys %{$s->{rules}{$f}{$pr}}){$i{$_}=1 for $ports{$n}?@{$s->{rules}{$f}{$pr}{$n}}:()}}}print join(',',grep {$i{$_}} @{ips($iv)}),"\n"}
    elsif($cmd eq 'changes'){
        my($old,$new)=(load($ARGV[0]),load($ARGV[1]));my $c=changes($old,$new);my $t=0;
        for my $f(qw(4 6)){next if same($old->{targets}{$f},$new->{targets}{$f});$t=1;print "  IPv$f target: ",join(', ',@{$old->{targets}{$f}}),' → ',join(', ',@{$new->{targets}{$f}}),"\n"}
        exit 3 unless @$c||$t;
        for(@$c){my($f,$pr,$n,$before,$after)=@$_;print "  IPv$f · $n/".uc($pr)."\n    Before: ",!defined($before)?'no restriction set':@$before?join(', ',@$before):'deny all sources',"\n    New: ",!defined($after)?'remove restriction':@$after?join(', ',@$after):'deny all sources',"\n"}
        print "  Reminder: protocols/ports whose restrictions were removed may become open to the public internet.\n" if grep {!defined $_->[4]} @$c;
    }
    elsif($cmd eq 'selection'){my($v,$count)=@ARGV;my %sel;if(lc($v)=~/\A(?:all|a|all |\*)\z/){$sel{$_}=1 for 0..$count-1}else{for(parts($v)){fail('Enter item numbers such as 1,3 or 1-3, or all to select everything') unless /\A([0-9]+)(?:-([0-9]+))?\z/;my($l,$r)=(0+$1,defined($2)?0+$2:0+$1);fail("Item number out of range 1-$count") unless 1<=$l&&$l<=$r&&$r<=$count;$sel{$_}=1 for $l-1..$r-1}}fail('Select at least one item') unless %sel;print "$_\n" for sort {$a<=>$b} keys %sel}
    elsif($cmd eq 'protos'){print join(',',@{protos($ARGV[0])}),"\n"}
    elsif($cmd eq 'state-lines'){my($p,$f)=@ARGV;my $s=load($p);for my $pr(qw(tcp udp)){for my $n(sort {$a<=>$b} keys %{$s->{rules}{$f}{$pr}}){print "allow\t$pr\t$n\t$_\n" for @{$s->{rules}{$f}{$pr}{$n}};print "deny\t$pr\t$n\n"}}for my $t(reverse @{$s->{targets}{$f}}){for my $pr(reverse qw(tcp udp)){print "hook\t$pr\t$t\n" if keys %{$s->{rules}{$f}{$pr}}}}}
    elsif($cmd eq 'snapshot-pack'){my $p=$ARGV[0];open my $h,'<:encoding(UTF-8)',$p or fail("Cannot read $p: $!");my $s={chains=>[],rules=>[],hooks=>[]};while(<$h>){my $a=$json->decode($_);my $t=shift @$a;if($t eq 'chain'){push @{$s->{chains}},$a->[0]}elsif($t eq 'rule'){push @{$s->{rules}},$a}elsif($t eq 'hook'){my $n=shift @$a;push @{$s->{hooks}},{position=>0+$n,args=>$a}}else{fail('Invalid snapshot record')}}close $h;emit(snapshot_valid($s))}
    elsif($cmd eq 'snapshot-unpack'){my $s=snapshot_valid(readjson($ARGV[0]));for(@{$s->{chains}}){print "chain\0"."1\0$_\0"}for(@{$s->{rules}}){print "rule\0".scalar(@$_)."\0",join("\0",@$_),"\0"}for(@{$s->{hooks}}){my @a=("$_->{position}",@{$_->{args}});print "hook\0".scalar(@a)."\0",join("\0",@a),"\0"}}
    elsif($cmd eq 'journal-make'){my($sp,$p4,$p6,$lp)=@ARGV;my %s;for my $f(qw(4 6)){my $p=$f eq '4'?$p4:$p6;$s{$f}=snapshot_valid(readjson($p)) if length $p}my $j={snapshots=>\%s,state=>-e($sp)?text($sp):undef};if(defined($lp)&&length($lp)){$j->{logging}=$lp eq '-'?undef:text($lp);logging_settings_valid($json->decode($j->{logging})) if defined $j->{logging}}emit($j)}
    elsif($cmd eq 'journal-families'){my $j=journal($ARGV[0]);print "$_\n" for sort keys %{$j->{snapshots}}}
    elsif($cmd eq 'journal-snapshot'){my $j=journal($ARGV[0]);emit($j->{snapshots}{$ARGV[1]})}
    elsif($cmd eq 'journal-state'){my $j=journal($ARGV[0]);exit 3 unless defined $j->{state};print $j->{state}}
    elsif($cmd eq 'journal-log-settings'){my $j=journal($ARGV[0]);exit 3 unless exists $j->{logging};exit 4 unless defined $j->{logging};print $j->{logging}}
    elsif($cmd eq 'live-json'){
        my @p=@ARGV; my %fam; my $managed=0;
        for my $i(0,1){
            my $f=$i==0?4:6; my($rules,$chains)=saverules($p[$i]//''); my %by=map {$_->{name}=>$_} @$chains;
            $_->{rules}=[] for values %by;
            my @hooks;
            for my $r(@$rules){if(exists $by{$r->{chain}}){push @{$by{$r->{chain}}{rules}},$r}elsif(defined($r->{target})&&exists $by{$r->{target}}){push @hooks,$r}}
            $managed+=scalar @$chains;
            $fam{$f}={available=>(defined($p[$i])&&length($p[$i])&&-e $p[$i])?JSON::PP::true:JSON::PP::false,chains=>[map {$by{$_}} sort keys %by],hooks=>\@hooks};
        }
        emit({version=>1,managed=>$managed,families=>\%fam});
    }
    elsif($cmd eq 'target-impact'){
        my($old,$new)=(load($ARGV[0]),load($ARGV[1]));my $changed=0;
        for my $f(qw(4 6)){
            my($a,$b)=($old->{targets}{$f},$new->{targets}{$f});
            next if same($a,$b);
            $changed=1;
            my(%ports,%sources);my($rules,$combos)=(0,0);
            for my $pr(qw(tcp udp)){for my $n(keys %{$new->{rules}{$f}{$pr}}){$ports{$n}=1;$combos++;$rules+=@{$new->{rules}{$f}{$pr}{$n}};$sources{$_}=1 for @{$new->{rules}{$f}{$pr}{$n}}}}
            fail("IPv$f already has port rules but the target host address is empty; consistency check failed, keep at least one IPv$f target host address") if !@$b&&%ports;
            if(%ports){print "  IPv$f target: ",@$a?join(', ',@$a):'not configured',' → ',@$b?join(', ',@$b):'not configured',"\n";print "    Impact: ",scalar(keys %ports)," ports ($combos port/protocol combinations), ",scalar(keys %sources)," sources, $rules allowlist entries in total will now apply to the new target;\n         the previous target addresses are no longer governed by these rules.\n"}
        }
        exit 3 unless $changed;
    }
    elsif($cmd eq 'state-from-snapshot'){
        my @p=@ARGV; my $s=empty(); my $found=0;
        for my $i(0,1){
            my $f=$i==0?4:6; my $path=$p[$i];
            next unless defined($path)&&length($path)&&$path ne '-'&&-e $path;
            my $snap=snapshot_valid(readjson($path)); my(%targets,%agg);
            repair_fail() if @{$snap->{chains}}>1;
            for my $h(@{$snap->{hooks}}){
                my $fields=rebuild_fields($h->{args},'hook');
                my $proto=$fields->{proto}; my $dest=$fields->{dest};
                fail("IPv$f managed chain hook is missing its target address or protocol; cannot rebuild state") unless defined($proto)&&defined($dest);
                fail("IPv$f managed chain hook has an invalid protocol: $proto") unless $proto eq 'tcp'||$proto eq 'udp';
                my($n,$nf,$pre)=ipnet($dest);
                fail("IPv$f managed chain hook target must be a single host address of this family: $dest") unless $nf eq $f&&$pre==($f eq '4'?32:128);
                $targets{$proto}{$n}=1;
            }
            for my $r(@{$snap->{rules}}){
                my(undef,$chain,@a)=@$r;
                next if rebuild_log(\@a);
                my $fields=rebuild_fields(\@a,'rule');
                my($proto,$port,$src,$jump)=@{$fields}{qw(proto port src jump)};
                fail("IPv$f managed chain $chain has a rule without protocol or port; cannot rebuild state") unless defined($proto)&&defined($port);
                fail("IPv$f managed chain $chain has an invalid protocol: $proto") unless $proto eq 'tcp'||$proto eq 'udp';
                fail("IPv$f managed chain $chain has an invalid port: $port") unless $port=~/\A[1-9][0-9]*\z/&&$port<=65535;
                fail("IPv$f managed chain $chain has an invalid action: ".($jump//'missing'),"; do not add rules to managed chains by hand") unless defined($jump)&&($jump eq 'RETURN'||$jump eq 'DROP');
                if($jump eq 'DROP'){
                    fail("IPv$f managed chain $chain has a DROP rule with a source address; cannot rebuild state") if defined $src;
                    repair_fail() if $agg{$proto}{0+$port}{drop};
                    $agg{$proto}{0+$port}{drop}=1;next;
                }
                fail("IPv$f managed chain $chain has an allow rule without a source address") unless defined($src);
                repair_fail() if $agg{$proto}{0+$port}{drop};
                my($sn,$sf)=ipnet($src); fail("IPv$f managed chain $chain source family mismatch: $src") unless $sf eq $f;
                push @{$agg{$proto}{0+$port}{sources}},$sn unless grep {$_ eq $sn} @{$agg{$proto}{0+$port}{sources}||[]};
            }
            for my $pr(qw(tcp udp)){for my $n(keys %{$agg{$pr}||{}}){
                fail("IPv$f port $n/$pr is missing its deny fallback rule (DROP); live rules do not match the state model, rebuild refused") unless $agg{$pr}{$n}{drop};
                $s->{rules}{$f}{$pr}{$n}=$agg{$pr}{$n}{sources}||[];$found=1;
            }}
            my @active=grep {keys %{$s->{rules}{$f}{$_}}} qw(tcp udp);
            if(@active){
                my @wanted=sort keys %{$targets{$active[0]}||{}};
                repair_fail() unless @wanted;
                for my $pr(@active){repair_fail() unless join(',',@wanted) eq join(',',sort keys %{$targets{$pr}||{}})}
                $s->{targets}{$f}=\@wanted;
            }
        }
        fail('The kernel has no managed rules, so state cannot be rebuilt from live rules; use rebuild as empty state instead') unless $found;
        emit(normalize($s));
    }
    else{fail("Unknown data operation: $cmd")}
    1;
};if(!$ok){my $e=$@||'Data processing failed';$e=~s/ at .* line \d+.*//s;print STDERR "Error: $e";print STDERR "\n" unless $e=~/\n\z/;exit 2}
PERL
}
log_data() {
    perl - "$LOGDIR" "$@" <<'PERL'
#!/usr/bin/env perl
# logging-engine.pl - storage engine for the ip-port-allowlist log feature.
#
# This file is embedded verbatim into the log_data() shell function of
# script/ip-port-allowlist.sh (quoted heredoc, program on stdin, ARGV from the
# caller).  It must therefore stay a single self contained Perl program:
#   * core modules only (JSON::PP, Fcntl, File::Temp, Cwd, POSIX, Time::HiRes,
#     Digest::SHA, File::Basename, File::Spec, Errno, B), no non core modules,
#     no python/jq/logrotate/daemon/systemd helper.
#   * every comment is ASCII only, every user visible message is a literal in
#     the %MSG table below so that allowlist-i18n-build.mjs can substitute it.
#   * no line is exactly the heredoc terminator (PERL/EOF/EOT) and there is no
#     __END__ or __DATA__ token.
#
# Usage: perl logging-engine.pl LOGDIR COMMAND [ARGS...]
#   LOGDIR is fixed by the caller: <stateDIR>/.ip-port-allowlist.logs
#
# Commands:
#   prefix
#   settings-json | settings-text | settings-propose KEY VALUE | settings-save FILE
#   settings-raw | settings-remove
#   audit ACTION EXITCODE DETAIL
#   cursor-json | cursor-fields
#   import INPUT_JSONL
#   view TYPE LIMIT FORMAT
#   stats-json | stats-text
#   rotate TYPE
#   clear TYPE CONFIRM
#   maintain
#
# Exit codes: 0 ok, 2 usage/storage/validation error, 3 settings-raw with no file.
#
# Storage rules enforced here:
#   * parent of LOGDIR: root owned real directory, not group/world writable.
#   * LOGDIR: real directory (never a symlink), root owned, mode 0700.
#   * every file touched inside LOGDIR: root owned regular file, nlink 1, 0600.
#     symlinks, hard links, sockets, fifos and devices are rejected, never
#     repaired and never silently recreated.
#   * one lock file inside LOGDIR (0600); every read, append, rotation and
#     maintenance sequence runs under flock(LOCK_EX) on it.
#   * only whitelisted names are touched: settings.json, cursor.json,
#     operations.jsonl, connections.jsonl, <stream>.jsonl.1 .. <stream>.jsonl.20,
#     the lock file and the two atomic-write temp prefixes.
#   * settings.json and cursor.json are replaced through an exclusive temp file
#     in the same directory, chmod 0600, sync -f file, rename, sync -f dir.

use strict;
use warnings;
use utf8;

use JSON::PP ();
use Fcntl qw(:DEFAULT :flock :mode);
use POSIX ();
use B ();
use Digest::SHA ();
use File::Temp ();
use File::Basename ();
use File::Spec ();
use Cwd ();
use Time::HiRes ();
use Errno qw(ENOENT EEXIST);

my $O_NOFOLLOW = defined(&Fcntl::O_NOFOLLOW) ? Fcntl::O_NOFOLLOW() : 0;

binmode STDOUT, ':encoding(UTF-8)';
binmode STDERR, ':encoding(UTF-8)';

# --------------------------------------------------------------- constants
my $LOGDIR_NAME     = '.ip-port-allowlist.logs';
my $LOCK_NAME       = '.lock';
my $SETTINGS_NAME   = 'settings.json';
my $CURSOR_NAME     = 'cursor.json';
my $STREAM_SUFFIX   = '.jsonl';
my $MAX_ARCHIVES    = 20;
my $MAX_RECORD_CHARS = 4000;
my $MAX_LINE_BYTES  = 1048576;
my $MAX_IMPORT_LINES = 1000;
my $MAX_IMPORT_BYTES = 8388608;
my $MAX_INPUT_BYTES = 65536;
my $MAX_CURSOR_BYTES = 4096;
my $MAX_TAIL_BYTES  = 8388608;
my $MIB             = 1048576;

my $JSON  = JSON::PP->new->canonical(1)->ascii(1);
my $JSONU = JSON::PP->new->canonical(1)->utf8(1);

my $LOGDIR;
my $CMD;
my $LOCK_FH;
my $SETTINGS_CACHE;
my $SETTINGS_PRESENT = 0;
my $CURSOR_PRESENT = 0;
# ---------------------------------------------------------------- messages
# Every visible string lives here exactly once.  Values are single quoted and
# must stay free of apostrophes, backslashes and double quotes so that the i18n
# substitution keeps the program valid for both languages.
my %MSG = (
    err_prefix                => 'Log engine error: ',
    warn_prefix               => 'Log engine warning: ',
    err_usage                 => 'Usage: logging-engine.pl LOGDIR COMMAND [ARGS...]',
    err_unknown_command       => 'Unknown command %s',
    err_missing_args          => 'Command %s is missing arguments',
    err_extra_args            => 'Command %s does not accept the extra argument %s',
    err_internal              => 'Internal error: %s',
    err_sync                  => 'Could not sync %s (exit status %s)',
    err_logdir_absolute       => 'LOGDIR must be an absolute path: %s',
    err_logdir_name           => 'The log directory name must be %s but is %s',
    err_parent_missing        => 'The parent directory of the log directory does not exist: %s',
    err_parent_not_dir        => 'The parent directory of the log directory is not a real directory (missing, symlink or special file): %s',
    err_parent_owner          => 'The parent directory of the log directory is not owned by root (uid %s): %s',
    err_parent_mode           => 'The parent directory of the log directory is writable by group or others (mode %s): %s',
    err_logdir_special        => 'The log directory is not a real directory (symlink or special file): %s',
    err_logdir_owner          => 'The log directory is not owned by root (uid %s): %s',
    err_logdir_mode           => 'The log directory mode is %s but must be 0700: %s',
    err_logdir_stat           => 'Could not stat the log directory %s: %s',
    err_logdir_create         => 'Could not create the log directory %s: %s',
    label_file_lock           => 'lock file',
    label_file_settings       => 'settings file',
    label_file_cursor         => 'cursor file',
    label_file_log            => 'log file',
    label_file_archive        => 'archive file',
    label_file_input          => 'input file',
    err_file_special          => 'The %s is not a regular file owned by root (symlink, hard link or special file): %s',
    err_file_owner            => 'The %s is not owned by root (uid %s): %s',
    err_file_nlink            => 'The %s has link count %s but it must be 1: %s',
    err_file_mode             => 'The %s mode is %s but it must be 0600: %s',
    err_file_stat             => 'Could not stat the %s: %s',
    err_file_read             => 'Could not read the %s: %s',
    err_file_write            => 'Could not write the %s: %s',
    err_file_open             => 'Could not open the %s: %s',
    err_file_rename           => 'Could not rename %s to %s: %s',
    err_file_unlink           => 'Could not delete %s: %s',
    err_file_chmod            => 'Could not set the mode of %s to 0600: %s',
    err_file_create           => 'Could not create %s: %s',
    err_dir_create            => 'Could not create the directory %s: %s',
    err_lock_open             => 'Could not open the lock file %s: %s',
    err_lock_flock            => 'Could not lock %s: %s',
    err_skip_unsafe           => 'Skipped an unsafe file and did not delete it: %s',
    err_settings_json         => 'The settings file is not valid JSON: %s: %s',
    err_settings_not_object   => 'The settings content must be a JSON object',
    err_settings_version      => 'The settings version %s is invalid; only the integer 1 is supported',
    err_settings_missing_key  => 'The settings are missing the key %s',
    err_settings_unknown_key  => 'The settings contain the unknown key %s',
    err_settings_type         => 'The setting %s must be an integer',
    err_settings_enum         => 'The value %s of the setting %s is invalid; allowed values: %s',
    err_settings_range        => 'The value %s of the setting %s is invalid; valid range: %s to %s',
    err_settings_input_json   => 'The input file is not valid JSON: %s: %s',
    err_cursor_json           => 'The cursor file is not valid JSON: %s: %s',
    err_cursor_not_object     => 'The cursor content must be a JSON object',
    err_cursor_unknown_key    => 'The cursor contains the unknown key %s',
    err_cursor_field          => 'The cursor field %s is missing or has the wrong type',
    err_import_lines          => 'The input file has %s lines, above the limit of %s',
    err_import_bytes          => 'The input file exceeds the %s byte limit',
    err_import_json           => 'Input line %s is not valid JSON: %s',
    err_import_object         => 'Input line %s is not a JSON object',
    err_import_field          => 'Input line %s field %s is missing or has the wrong type',
    err_record_long           => 'The record is longer than the %s byte limit',
    err_log_line_long         => 'The log line exceeds the %s byte limit: %s',
    err_view_json             => 'The log file %s is not valid JSON: %s',
    err_view_schema           => 'The log file %s has an invalid record structure',
    err_bad_type              => 'The log type %s is invalid; allowed values: operations, connections, both',
    err_bad_format            => 'The output format %s is invalid; allowed values: json, text',
    err_bad_limit             => 'The line count %s is invalid; it must be an integer between 1 and 1000',
    err_bad_exit_code         => 'The exit code %s is invalid; it must be an integer between 0 and 255',
    err_bad_action            => 'The action %s is invalid; only lowercase letters, digits, underscores and hyphens are allowed, length 1 to 64',
    err_bad_confirm           => 'The confirmation string is wrong; type CLEAR exactly',
    err_bad_setting_key       => 'The setting key %s is invalid; allowed keys: operations, connections, max_mib, keep, retention_days, rate, burst, auto_rotate',
    label_settings_header     => 'Log engine settings',
    label_settings_line       => '%s: %s',
    label_version             => 'Config version',
    label_operations          => 'Operations log',
    label_connections         => 'Connections log',
    label_both                => 'Operations and connections logs',
    label_max_mib             => 'Maximum size per file (MiB)',
    label_keep                => 'Files to keep',
    label_retention_days      => 'Retention days',
    label_rate                => 'Connections log rate limit (per minute)',
    label_burst               => 'Connections log burst',
    label_auto_rotate         => 'Automatic rotation',
    decision_allow            => 'allow',
    decision_deny             => 'deny',
    fmt_text_operation        => '%s operation %s exit code=%s %s',
    fmt_text_connection       => '%s connection %s %s:%s to %s:%s protocol=%s in=%s out=%s %s',
    msg_rotate_done           => 'Rotated %s',
    msg_rotate_empty          => 'The active log of %s is empty; nothing was rotated',
    msg_rotate_missing        => 'The active log of %s does not exist; nothing was rotated',
    msg_clear_done            => 'Cleared the log files of %s',
    msg_clear_mark            => 'The clear watermark was updated to %s microseconds',
    msg_settings_removed      => 'The settings file was deleted',
    msg_import_done           => 'Imported %s connection records, skipped %s duplicates, skipped %s records older than the clear watermark',
    msg_stats_logdir          => 'Log directory: %s',
    msg_stats_stream          => '%s: active file %s, %s bytes, %s records, %s archives',
    msg_stats_archive         => 'Archive %s: %s bytes',
    msg_stats_cursor          => 'Cursor file: %s',
    msg_stats_cursor_yes      => 'present',
    msg_stats_cursor_no       => 'absent',
    msg_stats_settings        => 'Current settings: ',
);

sub msg  { return $MSG{$_[0]} }
sub msgf {
    my ($key, @args) = @_;
    return sprintf($MSG{$key}, map { chars($_) } @args);
}

# ------------------------------------------------------------- basic output
sub chars {
    my ($s) = @_;
    return $s unless defined $s;
    return $s if utf8::is_utf8($s);
    my $copy = $s;
    return utf8::decode($copy) ? $copy : $s;
}
sub out {
    my @a = @_;
    print STDOUT map { chars($_) } @a;
    return 1;
}
sub outl {
    my @a = @_;
    push @a, "\n";
    print STDOUT map { chars($_) } @a;
    return 1;
}
sub errl {
    my @a = @_;
    push @a, "\n";
    print STDERR map { chars($_) } @a;
    return 1;
}
sub warnl { return errl($MSG{warn_prefix} . $_[0]) }
sub fail {
    errl($MSG{err_prefix} . $_[0]);
    exit 2;
}
$SIG{__WARN__} = sub {
    my $m = $_[0];
    $m =~ s/\s+\z//;
    errl($MSG{warn_prefix} . chars($m));
};

sub describe {
    my ($v) = @_;
    return 'null' unless defined $v;
    return '<array>' if ref $v eq 'ARRAY';
    return '<object>' if ref $v eq 'HASH';
    return '<ref>' if ref $v;
    my $s = sanitize_human(chars($v));
    $s = substr($s, 0, 40) . '...' if length($s) > 40;
    return $s;
}

sub sanitize_human {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/\x1b\[[0-9;?]*[ -\/]*[@-~]//g;
    $s =~ s/\x1b[()][A-Za-z0-9]//g;
    $s =~ s/\x1b[@-Z\\\-_]//g;
    $s =~ s/\x1b//g;
    $s =~ s/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]//g;
    $s =~ s/[\x{80}-\x{9f}]//g;
    $s =~ s/[\t\r\n]+/ /g;
    return $s;
}

sub bounded {
    my ($s, $max) = @_;
    $s = '' unless defined $s;
    return $s if length($s) <= $max;
    return substr($s, 0, $max);
}

# ------------------------------------------------------------ type helpers
sub is_int {
    my ($v) = @_;
    return 0 if !defined $v || ref $v;
    my $f = B::svref_2object(\$v)->FLAGS;
    return 0 if $f & B::SVp_POK();
    return ($f & B::SVp_IOK()) ? 1 : 0;
}
sub is_num {
    my ($v) = @_;
    return 0 if !defined $v || ref $v;
    my $f = B::svref_2object(\$v)->FLAGS;
    return 0 if $f & B::SVp_POK();
    return ($f & (B::SVp_IOK() | B::SVp_NOK())) ? 1 : 0;
}
sub is_str {
    my ($v) = @_;
    return 0 if !defined $v || ref $v;
    my $f = B::svref_2object(\$v)->FLAGS;
    return ($f & B::SVp_POK()) ? 1 : 0;
}
sub is_plain_int {
    my ($v) = @_;
    return 0 unless defined $v && !ref $v;
    return $v =~ /\A(?:0|[1-9][0-9]*)\z/ ? 1 : 0;
}
sub is_cursor_ok {
    my ($s) = @_;
    return 0 unless defined $s && !ref $s;
    return 0 if length($s) < 1 || length($s) > $MAX_CURSOR_BYTES;
    return 0 if $s =~ /[\x00-\x1f\x7f]/;
    return 1;
}

# ---------------------------------------------------- security predicates
# Kept as tiny named predicates so that a local, clearly separate test mutation
# layer can stub the uid/mode/nlink checks on a machine that has no root.  The
# product behaviour is the body of these functions.
sub owner_is_root { my ($uid) = @_; return $uid == 0 }
sub mode_is       { my ($mode, $want) = @_; return ($mode & 07777) == $want }
sub nlink_is_one  { my ($n) = @_; return $n == 1 }
sub is_regular    { my ($mode) = @_; return S_ISREG($mode) ? 1 : 0 }
sub is_dir        { my ($mode) = @_; return S_ISDIR($mode) ? 1 : 0 }
sub is_symlink    { my ($mode) = @_; return S_ISLNK($mode) ? 1 : 0 }
sub parent_mode_ok { my ($mode) = @_; return ((($mode & 07777) & 0022) == 0) ? 1 : 0 }

sub check_st {
    my ($st, $path, $label) = @_;
    fail(msgf('err_file_special', $label, $path)) if is_symlink($st->[2]) || !is_regular($st->[2]);
    fail(msgf('err_file_owner', $label, $st->[4], $path)) unless owner_is_root($st->[4]);
    fail(msgf('err_file_nlink', $label, $st->[3], $path)) unless nlink_is_one($st->[3]);
    fail(msgf('err_file_mode', $label, sprintf('0%o', $st->[2] & 07777), $path)) unless mode_is($st->[2], 0600);
    return 1;
}
sub file_ok {
    my ($path, $label) = @_;
    my @st = lstat($path);
    return 0 unless @st;
    check_st(\@st, $path, $label);
    return 1;
}
sub fh_ok {
    my ($fh, $path, $label) = @_;
    my @st = stat($fh);
    fail(msgf('err_file_stat', $path, $!)) unless @st;
    check_st(\@st, $path, $label);
    return 1;
}
sub legal_regular {
    my ($path) = @_;
    my @st = lstat($path);
    return 0 unless @st;
    return 0 if is_symlink($st[2]) || !is_regular($st[2]);
    return 0 unless owner_is_root($st[4]);
    return 0 unless nlink_is_one($st[3]);
    return 0 unless mode_is($st[2], 0600);
    return 1;
}

# --------------------------------------------------------------- path util
sub normalize_abs {
    my ($p) = @_;
    my @out;
    for my $c (split m{/}, $p) {
        next if $c eq '' || $c eq '.';
        if ($c eq '..') { pop @out if @out; next }
        push @out, $c;
    }
    return '/' . join('/', @out);
}

sub canon_path {
    my ($p) = @_;
    my $abs = ($p =~ m{\A/}) ? normalize_abs($p) : normalize_abs(File::Spec->rel2abs($p));
    my @parts = split m{/}, $abs;
    my @tail;
    while (1) {
        my $cand = @parts ? join('/', @parts) : '';
        $cand = '/' if $cand eq '';
        my $real = Cwd::abs_path($cand);
        if (defined $real && length $real) {
            $real = chars($real);
            my $joined = @tail ? $real . '/' . join('/', reverse @tail) : $real;
            return normalize_abs($joined);
        }
        last if @parts <= 1;
        push @tail, pop @parts;
    }
    return $abs;
}

sub prefix_hex {
    my $canon = canon_path($LOGDIR);
    my $bytes = $canon;
    utf8::encode($bytes) if utf8::is_utf8($bytes);
    return substr(Digest::SHA::sha256_hex($bytes), 0, 10);
}

sub stream_path   { return $LOGDIR . '/' . $_[0] . $STREAM_SUFFIX }
sub archive_path  { return $LOGDIR . '/' . $_[0] . $STREAM_SUFFIX . '.' . $_[1] }
sub settings_path { return $LOGDIR . '/' . $SETTINGS_NAME }
sub cursor_path   { return $LOGDIR . '/' . $CURSOR_NAME }
sub lock_path     { return $LOGDIR . '/' . $LOCK_NAME }

sub stream_label {
    my ($t) = @_;
    return $MSG{label_both} if $t eq 'both';
    return $MSG{label_operations} if $t eq 'operations';
    return $MSG{label_connections};
}

sub now_micro {
    my ($s, $u) = Time::HiRes::gettimeofday();
    my $us = $s * 1000000 + $u;
    return ($us, iso_utc($us));
}

sub iso_utc {
    my $us = 0 + $_[0];
    my $sec = int($us / 1000000);
    my $frac = $us - $sec * 1000000;
    my @t = gmtime($sec);
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02d.%06dZ',
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0], $frac);
}

sub sync_path {
    my ($path) = @_;
    my $rc = system('sync', '-f', $path);
    if ($rc != 0) {
        my $why = $rc == -1 ? "$!" : ($rc >> 8);
        fail(msgf('err_sync', $path, $why));
    }
    return 1;
}

# ---------------------------------------------------------- logdir handling
sub logdir_prepare {
    my ($create) = @_;
    my $name = File::Basename::basename($LOGDIR);
    fail(msgf('err_logdir_name', $LOGDIR_NAME, describe($name))) unless $name eq $LOGDIR_NAME;
    my $parent = File::Basename::dirname($LOGDIR);
    $parent = '/' if !length($parent) || $parent eq '.';
    my @pst = lstat($parent);
    fail(msgf('err_parent_missing', $parent)) unless @pst;
    fail(msgf('err_parent_not_dir', $parent)) if is_symlink($pst[2]) || !is_dir($pst[2]);
    fail(msgf('err_parent_owner', $pst[4], $parent)) unless owner_is_root($pst[4]);
    fail(msgf('err_parent_mode', sprintf('0%o', $pst[2] & 07777), $parent)) unless parent_mode_ok($pst[2]);
    my @lst = lstat($LOGDIR);
    if (!@lst) {
        my $errno = $!;
        fail(msgf('err_logdir_stat', $LOGDIR, $errno)) unless $errno == ENOENT;
        return 0 unless $create;
        mkdir($LOGDIR, 0700) or fail(msgf('err_dir_create', $LOGDIR, $!));
        @lst = lstat($LOGDIR);
        fail(msgf('err_logdir_stat', $LOGDIR, $!)) unless @lst;
    }
    fail(msgf('err_logdir_special', $LOGDIR)) if is_symlink($lst[2]) || !is_dir($lst[2]);
    fail(msgf('err_logdir_owner', $lst[4], $LOGDIR)) unless owner_is_root($lst[4]);
    fail(msgf('err_logdir_mode', sprintf('0%o', $lst[2] & 07777), $LOGDIR)) unless mode_is($lst[2], 0700);
    return 1;
}

sub lock_acquire {
    my $path = lock_path();
    my @st = lstat($path);
    if (!@st) {
        sysopen(my $fh, $path, O_RDWR | O_CREAT | O_EXCL | $O_NOFOLLOW, 0600)
            or fail(msgf('err_lock_open', $path, $!));
        close $fh or fail(msgf('err_lock_open', $path, $!));
        @st = lstat($path);
        fail(msgf('err_lock_open', $path, $!)) unless @st;
    }
    check_st(\@st, $path, $MSG{label_file_lock});
    sysopen(my $fh, $path, O_RDWR | $O_NOFOLLOW) or fail(msgf('err_lock_open', $path, $!));
    flock($fh, LOCK_EX) or fail(msgf('err_lock_flock', $path, $!));
    $LOCK_FH = $fh;
    return 1;
}

sub begin_storage {
    my ($create) = @_;
    my $have = logdir_prepare($create);
    return 0 unless $have;
    lock_acquire();
    return 1;
}

# ------------------------------------------------------------ file helpers
sub read_raw_file {
    my ($path, $label, $maxbytes) = @_;
    file_ok($path, $label) or return undef;
    my $size = -s $path;
    if (defined $maxbytes && defined $size && $size > $maxbytes) {
        fail(msgf('err_import_bytes', $maxbytes));
    }
    open(my $fh, '<:raw', $path) or fail(msgf('err_file_read', $path, $!));
    local $/;
    my $data = <$fh>;
    close $fh or fail(msgf('err_file_read', $path, $!));
    return defined $data ? $data : '';
}

sub read_input_file {
    my ($path, $maxbytes) = @_;
    my @st = lstat($path);
    fail(msgf('err_file_read', $path, $!)) unless @st;
    fail(msgf('err_file_special', $MSG{label_file_input}, $path))
        if is_symlink($st[2]) || !is_regular($st[2]);
    fail(msgf('err_import_bytes', $maxbytes)) if $st[7] > $maxbytes;
    open(my $fh, '<:raw', $path) or fail(msgf('err_file_read', $path, $!));
    local $/;
    my $data = <$fh>;
    close $fh or fail(msgf('err_file_read', $path, $!));
    return defined $data ? $data : '';
}

sub atomic_write {
    my ($path, $data, $label, $template) = @_;
    file_ok($path, $label);
    my ($fh, $tmp) = File::Temp::tempfile($template, DIR => $LOGDIR, UNLINK => 0);
    fail(msgf('err_file_create', $path, $!)) unless defined $fh && defined $tmp;
    print {$fh} $data or fail(msgf('err_file_write', $tmp, $!));
    eval { POSIX::fsync(fileno($fh)) };
    close $fh or fail(msgf('err_file_write', $tmp, $!));
    chmod(0600, $tmp) or fail(msgf('err_file_chmod', $tmp, $!));
    my @st = lstat($tmp);
    fail(msgf('err_file_stat', $tmp, $!)) unless @st;
    check_st(\@st, $tmp, $label);
    sync_path($tmp);
    rename($tmp, $path) or fail(msgf('err_file_rename', $tmp, $path, $!));
    sync_path($LOGDIR);
    return 1;
}

sub json_decode_bytes {
    my ($bytes, $errkey, $path) = @_;
    my $data = eval { $JSONU->decode($bytes) };
    if (!defined $data) {
        my $e = $@ || 'unknown';
        $e =~ s/\s+\z//;
        fail(msgf($errkey, $path, describe($e)));
    }
    return $data;
}

# -------------------------------------------------------------- settings
my @SETTING_KEYS = qw(operations connections max_mib keep retention_days rate burst auto_rotate);
my %SPEC = (
    operations     => { type => 'enum', values => ['on', 'off'] },
    connections    => { type => 'enum', values => ['off', 'deny', 'all'] },
    max_mib        => { type => 'int', min => 1, max => 100 },
    keep           => { type => 'int', min => 1, max => 20 },
    retention_days => { type => 'int', min => 0, max => 365 },
    rate           => { type => 'int', min => 1, max => 100 },
    burst          => { type => 'int', min => 1, max => 100 },
    auto_rotate    => { type => 'enum', values => ['on', 'off'] },
);

sub default_settings {
    return {
        version        => 1,
        operations     => 'on',
        connections    => 'off',
        max_mib        => 10,
        keep           => 5,
        retention_days => 30,
        rate           => 10,
        burst          => 5,
        auto_rotate    => 'on',
    };
}

sub validate_setting_value {
    my ($key, $v) = @_;
    my $spec = $SPEC{$key};
    if ($spec->{type} eq 'enum') {
        fail(msgf('err_settings_type', $key)) unless is_str($v);
        fail(msgf('err_settings_enum', $key, describe($v), join(', ', @{$spec->{values}})))
            unless grep { $_ eq $v } @{$spec->{values}};
        return $v;
    }
    fail(msgf('err_settings_type', $key)) unless is_int($v);
    fail(msgf('err_settings_range', $key, describe($v), $spec->{min}, $spec->{max}))
        if $v < $spec->{min} || $v > $spec->{max};
    return 0 + $v;
}

sub validate_settings {
    my ($data) = @_;
    fail($MSG{err_settings_not_object}) unless ref($data) eq 'HASH';
    fail(msgf('err_settings_missing_key', 'version')) unless exists $data->{version};
    fail(msgf('err_settings_version', describe($data->{version})))
        unless is_int($data->{version}) && $data->{version} == 1;
    for my $k (sort keys %$data) {
        fail(msgf('err_settings_unknown_key', describe($k))) unless $k eq 'version' || exists $SPEC{$k};
    }
    my %out = (version => 1);
    for my $k (@SETTING_KEYS) {
        fail(msgf('err_settings_missing_key', $k)) unless exists $data->{$k};
        $out{$k} = validate_setting_value($k, $data->{$k});
    }
    return \%out;
}

sub load_settings {
    return $SETTINGS_CACHE if $SETTINGS_CACHE;
    my $path = settings_path();
    if (!file_ok($path, $MSG{label_file_settings})) {
        $SETTINGS_PRESENT = 0;
        $SETTINGS_CACHE = default_settings();
        return $SETTINGS_CACHE;
    }
    $SETTINGS_PRESENT = 1;
    my $raw = read_raw_file($path, $MSG{label_file_settings});
    my $data = json_decode_bytes($raw, 'err_settings_json', $path);
    $SETTINGS_CACHE = validate_settings($data);
    return $SETTINGS_CACHE;
}

sub settings_lines {
    my ($cfg) = @_;
    my @lines;
    push @lines, $MSG{label_settings_header};
    push @lines, msgf('label_settings_line', $MSG{label_version}, $cfg->{version});
    push @lines, msgf('label_settings_line', $MSG{label_operations}, $cfg->{operations});
    push @lines, msgf('label_settings_line', $MSG{label_connections}, $cfg->{connections});
    push @lines, msgf('label_settings_line', $MSG{label_max_mib}, $cfg->{max_mib});
    push @lines, msgf('label_settings_line', $MSG{label_keep}, $cfg->{keep});
    push @lines, msgf('label_settings_line', $MSG{label_retention_days}, $cfg->{retention_days});
    push @lines, msgf('label_settings_line', $MSG{label_rate}, $cfg->{rate});
    push @lines, msgf('label_settings_line', $MSG{label_burst}, $cfg->{burst});
    push @lines, msgf('label_settings_line', $MSG{label_auto_rotate}, $cfg->{auto_rotate});
    return @lines;
}

# ---------------------------------------------------------------- cursor
sub default_cursor {
    return { cursor => undef, boot_id => undef, clear_after_us => 0 };
}

sub load_cursor {
    my $path = cursor_path();
    if (!file_ok($path, $MSG{label_file_cursor})) {
        $CURSOR_PRESENT = 0;
        return default_cursor();
    }
    $CURSOR_PRESENT = 1;
    my $raw = read_raw_file($path, $MSG{label_file_cursor});
    my $data = json_decode_bytes($raw, 'err_cursor_json', $path);
    fail($MSG{err_cursor_not_object}) unless ref($data) eq 'HASH';
    for my $k (sort keys %$data) {
        fail(msgf('err_cursor_unknown_key', describe($k))) unless $k =~ /\A(?:cursor|boot_id|clear_after_us)\z/;
    }
    my $cur = exists $data->{cursor} ? $data->{cursor} : undef;
    if (defined $cur) {
        fail(msgf('err_cursor_field', 'cursor')) unless is_str($cur) && is_cursor_ok($cur);
    }
    my $boot = exists $data->{boot_id} ? $data->{boot_id} : undef;
    if (defined $boot) {
        fail(msgf('err_cursor_field', 'boot_id')) unless is_str($boot) && $boot =~ /\A[0-9a-f]{32}\z/;
    }
    my $clr = exists $data->{clear_after_us} ? $data->{clear_after_us} : 0;
    fail(msgf('err_cursor_field', 'clear_after_us')) unless is_int($clr) && $clr >= 0;
    return { cursor => $cur, boot_id => $boot, clear_after_us => 0 + $clr };
}

sub save_cursor {
    my ($cur) = @_;
    my %data = (
        cursor         => defined $cur->{cursor} ? $cur->{cursor} : undef,
        boot_id        => defined $cur->{boot_id} ? $cur->{boot_id} : undef,
        clear_after_us => 0 + $cur->{clear_after_us},
    );
    atomic_write(cursor_path(), $JSON->encode(\%data) . "\n", $MSG{label_file_cursor}, 'cursor.json.tmp.XXXXXX');
    $CURSOR_PRESENT = 1;
    return 1;
}

# ------------------------------------------------------- rotation / pruning
sub rotate_stream {
    my ($stream, $cfg) = @_;
    my $keep = $cfg->{keep};
    my $active = stream_path($stream);
    my $exists = file_ok($active, $MSG{label_file_log});
    return 'missing' unless $exists;
    my $size = -s $active;
    return 'empty' unless defined $size && $size > 0;
    my $oldest = archive_path($stream, $keep);
    if (file_ok($oldest, $MSG{label_file_archive})) {
        unlink($oldest) or fail(msgf('err_file_unlink', $oldest, $!));
    }
    for (my $n = $keep - 1; $n >= 1; $n--) {
        my $from = archive_path($stream, $n);
        my $to = archive_path($stream, $n + 1);
        next unless file_ok($from, $MSG{label_file_archive});
        rename($from, $to) or fail(msgf('err_file_rename', $from, $to, $!));
        chmod(0600, $to) or fail(msgf('err_file_chmod', $to, $!));
    }
    my $first = archive_path($stream, 1);
    rename($active, $first) or fail(msgf('err_file_rename', $active, $first, $!));
    chmod(0600, $first) or fail(msgf('err_file_chmod', $first, $!));
    my $now = int(Time::HiRes::time());
    utime($now, $now, $first);
    return 'rotated';
}

sub expire_archives {
    my ($stream, $cfg) = @_;
    my $keep = $cfg->{keep};
    for my $n ($keep + 1 .. $MAX_ARCHIVES) {
        my $p = archive_path($stream, $n);
        next unless file_ok($p, $MSG{label_file_archive});
        unlink($p) or fail(msgf('err_file_unlink', $p, $!));
    }
    return 1 unless $cfg->{retention_days} > 0;
    my $cutoff = int(Time::HiRes::time()) - $cfg->{retention_days} * 86400;
    for my $n (1 .. $keep) {
        my $p = archive_path($stream, $n);
        next unless file_ok($p, $MSG{label_file_archive});
        my @st = lstat($p);
        next unless @st;
        next unless $st[9] < $cutoff;
        unlink($p) or fail(msgf('err_file_unlink', $p, $!));
    }
    return 1;
}

# ------------------------------------------------------------ line readers
sub read_tail_lines {
    my ($path, $want) = @_;
    return () if $want <= 0;
    open(my $fh, '<:raw', $path) or fail(msgf('err_file_read', $path, $!));
    my $size = -s $path;
    if (!defined $size || $size == 0) { close $fh; return () }
    my $pos = $size;
    my $chunk = 65536;
    my $buf = '';
    while ($pos > 0) {
        my $len = $pos > $chunk ? $chunk : $pos;
        $pos -= $len;
        sysseek($fh, $pos, 0) or fail(msgf('err_file_read', $path, $!));
        my $data = '';
        my $got = sysread($fh, $data, $len);
        fail(msgf('err_file_read', $path, $!)) unless defined $got && $got == $len;
        $buf = $data . $buf;
        fail(msgf('err_log_line_long', $MAX_TAIL_BYTES, $path)) if length($buf) > $MAX_TAIL_BYTES;
        my $nl = ($buf =~ tr/\n//);
        last if $nl >= $want + 1;
    }
    close $fh;
    my $complete = $buf;
    $complete =~ s/\n\z//;
    my @lines = split /\n/, $complete, -1;
    shift @lines if $pos > 0;
    @lines = @lines[-$want .. -1] if @lines > $want;
    return @lines;
}

sub count_lines {
    my ($path) = @_;
    open(my $fh, '<:raw', $path) or fail(msgf('err_file_read', $path, $!));
    my $count = 0;
    while (my $line = <$fh>) {
        fail(msgf('err_log_line_long', $MAX_LINE_BYTES, $path)) if length($line) > $MAX_LINE_BYTES;
        $count++;
    }
    close $fh or fail(msgf('err_file_read', $path, $!));
    return $count;
}

sub collect_tail_lines {
    my ($stream, $limit) = @_;
    my @lines;
    my $active = stream_path($stream);
    if (file_ok($active, $MSG{label_file_log})) {
        push @lines, reverse read_tail_lines($active, $limit);
    }
    for (my $n = 1; $n <= $MAX_ARCHIVES && @lines < $limit; $n++) {
        my $p = archive_path($stream, $n);
        next unless file_ok($p, $MSG{label_file_archive});
        push @lines, reverse read_tail_lines($p, $limit - @lines);
    }
    return @lines;
}

# -------------------------------------------------------------- records
sub parse_kernel_header {
    my ($body) = @_;
    my %h = (SRC => undef, DST => undef, PROTO => undef, SPT => undef, DPT => undef, IN => undef, OUT => undef);
    for my $tok (split /\s+/, (defined $body ? $body : '')) {
        my ($k, $v) = split /=/, $tok, 2;
        next unless defined $k && defined $v;
        next unless exists $h{$k};
        $h{$k} = $v;
    }
    for my $k (qw(SRC DST PROTO IN OUT)) {
        next unless defined $h{$k};
        my $v = sanitize_human(chars($h{$k}));
        $h{$k} = length($v) ? bounded($v, 256) : undef;
    }
    $h{PROTO} = lc $h{PROTO} if defined $h{PROTO};
    $h{PROTO} = undef if defined $h{PROTO} && $h{PROTO} !~ /\A[a-z0-9]{1,16}\z/;
    for my $k (qw(SPT DPT)) {
        if (defined $h{$k} && $h{$k} =~ /\A[0-9]{1,5}\z/ && $h{$k} <= 65535) {
            $h{$k} = 0 + $h{$k};
        } else {
            $h{$k} = undef;
        }
    }
    return \%h;
}

sub parse_record_line {
    my ($line, $path, $stream) = @_;
    my $rec = eval { $JSONU->decode($line) };
    if (!defined $rec) {
        my $e = $@ || 'unknown';
        $e =~ s/\s+\z//;
        fail(msgf('err_view_json', $path, describe($e)));
    }
    fail(msgf('err_view_schema', $path)) unless ref($rec) eq 'HASH';
    fail(msgf('err_view_schema', $path)) unless is_str($rec->{type});
    my $want = $stream eq 'operations' ? 'operation' : 'connection';
    fail(msgf('err_view_schema', $path)) unless $rec->{type} eq $want;
    fail(msgf('err_view_schema', $path)) unless is_num($rec->{time_us});
    return $rec;
}

sub text_or_dash {
    my ($v, $max) = @_;
    return '-' unless defined $v && !ref $v;
    my $s = sanitize_human(chars($v));
    $s = bounded($s, $max) if defined $max;
    return length($s) ? $s : '-';
}

sub render_text_record {
    my ($r) = @_;
    my $t = text_or_dash($r->{time}, 64);
    if ($r->{type} eq 'operation') {
        my $action = text_or_dash($r->{action}, 64);
        my $code = defined $r->{exit_code} && !ref $r->{exit_code} ? $r->{exit_code} : '-';
        my $detail = text_or_dash($r->{detail}, 300);
        return msgf('fmt_text_operation', $t, $action, $code, $detail);
    }
    my $dec = $r->{decision};
    $dec = (defined $dec && $dec eq 'allow') ? $MSG{decision_allow}
         : (defined $dec && $dec eq 'deny') ? $MSG{decision_deny} : '-';
    return msgf('fmt_text_connection', $t, $dec,
        text_or_dash($r->{src}, 256), text_or_dash($r->{source_port}, 8),
        text_or_dash($r->{dst}, 256), text_or_dash($r->{dest_port}, 8),
        text_or_dash($r->{proto}, 16), text_or_dash($r->{input}, 64),
        text_or_dash($r->{output}, 64), text_or_dash($r->{message}, 300));
}

sub append_line {
    my ($stream, $line) = @_;
    fail(msgf('err_record_long', $MAX_LINE_BYTES)) if length($line) > $MAX_LINE_BYTES;
    my $cfg = load_settings();
    my $active = stream_path($stream);
    my $limit = $cfg->{max_mib} * $MIB;
    my $exists = file_ok($active, $MSG{label_file_log});
    if ($cfg->{auto_rotate} eq 'on' && $exists) {
        my $size = -s $active;
        if (defined $size && ($size >= $limit || $size + length($line) > $limit)) {
            rotate_stream($stream, $cfg);
        }
    }
    my $path = stream_path($stream);
    sysopen(my $fh, $path, O_WRONLY | O_APPEND | O_CREAT | $O_NOFOLLOW, 0600)
        or fail(msgf('err_file_open', $path, $!));
    fh_ok($fh, $path, $MSG{label_file_log});
    print {$fh} $line or fail(msgf('err_file_write', $path, $!));
    close $fh or fail(msgf('err_file_write', $path, $!));
    return 1;
}

# --------------------------------------------------------- argument checks
sub arg_count {
    my ($cmd, $want, @args) = @_;
    fail(msgf('err_missing_args', $cmd)) if @args < $want;
    fail(msgf('err_extra_args', $cmd, describe($args[$want]))) if @args > $want;
    return @args;
}

sub check_type {
    my ($t) = @_;
    fail(msgf('err_bad_type', describe($t)))
        unless defined $t && ($t eq 'operations' || $t eq 'connections' || $t eq 'both');
    return $t;
}

sub check_limit {
    my ($v) = @_;
    fail(msgf('err_bad_limit', describe($v)))
        unless is_plain_int($v) && $v >= 1 && $v <= 1000;
    return 0 + $v;
}

# --------------------------------------------------------------- commands
sub cmd_prefix {
    arg_count('prefix', 0, @_);
    outl('IPW_' . prefix_hex());
    return 0;
}

sub cmd_settings_json {
    arg_count('settings-json', 0, @_);
    begin_storage(0);
    outl($JSON->encode(load_settings()));
    return 0;
}

sub cmd_settings_text {
    arg_count('settings-text', 0, @_);
    begin_storage(0);
    outl($_) for settings_lines(load_settings());
    return 0;
}

sub cmd_settings_propose {
    my @a = arg_count('settings-propose', 2, @_);
    my ($key, $value) = @a;
    fail(msgf('err_bad_setting_key', describe($key))) unless defined $key && exists $SPEC{$key};
    my $spec = $SPEC{$key};
    my $val;
    if ($spec->{type} eq 'enum') {
        fail(msgf('err_settings_enum', $key, describe($value), join(', ', @{$spec->{values}})))
            unless defined $value && !ref $value && grep { $_ eq $value } @{$spec->{values}};
        $val = $value;
    } else {
        fail(msgf('err_settings_type', $key)) unless is_plain_int($value);
        fail(msgf('err_settings_range', $key, describe($value), $spec->{min}, $spec->{max}))
            if $value < $spec->{min} || $value > $spec->{max};
        $val = 0 + $value;
    }
    begin_storage(0);
    my $cfg = load_settings();
    my %cand = %$cfg;
    $cand{$key} = $val;
    my $checked = validate_settings(\%cand);
    outl($JSON->encode($checked));
    return 0;
}

sub cmd_settings_save {
    my @a = arg_count('settings-save', 1, @_);
    my $file = chars($a[0]);
    my $raw = read_input_file($file, $MAX_INPUT_BYTES);
    my $data = eval { $JSONU->decode($raw) };
    if (!defined $data) {
        my $e = $@ || 'unknown';
        $e =~ s/\s+\z//;
        fail(msgf('err_settings_input_json', $file, describe($e)));
    }
    my $cfg = validate_settings($data);
    begin_storage(1);
    atomic_write(settings_path(), $JSON->encode($cfg) . "\n", $MSG{label_file_settings}, 'settings.json.tmp.XXXXXX');
    outl($JSON->encode($cfg));
    return 0;
}

sub cmd_settings_raw {
    arg_count('settings-raw', 0, @_);
    begin_storage(0);
    my $path = settings_path();
    return 3 unless file_ok($path, $MSG{label_file_settings});
    my $raw = read_raw_file($path, $MSG{label_file_settings});
    out($raw);
    return 0;
}

sub cmd_settings_remove {
    arg_count('settings-remove', 0, @_);
    begin_storage(0);
    my $path = settings_path();
    return 0 unless file_ok($path, $MSG{label_file_settings});
    unlink($path) or fail(msgf('err_file_unlink', $path, $!));
    sync_path($LOGDIR);
    outl($MSG{msg_settings_removed});
    return 0;
}

sub cmd_audit {
    my @a = arg_count('audit', 3, @_);
    my ($action, $code, $detail) = @a;
    fail(msgf('err_bad_action', describe($action)))
        unless defined $action && !ref $action && $action =~ /\A[a-z0-9_-]{1,64}\z/;
    fail(msgf('err_bad_exit_code', describe($code)))
        unless is_plain_int($code) && $code <= 255;
    $detail = '' unless defined $detail;
    $detail = bounded(sanitize_human(chars($detail)), $MAX_RECORD_CHARS);
    my $have = begin_storage(0);
    my $cfg = load_settings();
    return 0 unless $cfg->{operations} eq 'on';
    if (!$have) {
        begin_storage(1);
        $cfg = load_settings();
        return 0 unless $cfg->{operations} eq 'on';
    }
    my ($us, $iso) = now_micro();
    my $rec = {
        type      => 'operation',
        time      => $iso,
        time_us   => $us,
        action    => $action,
        exit_code => 0 + $code,
        detail    => $detail,
        pid       => 0 + $$,
    };
    append_line('operations', $JSON->encode($rec) . "\n");
    return 0;
}

sub cmd_cursor_json {
    arg_count('cursor-json', 0, @_);
    begin_storage(0);
    my $cur = load_cursor();
    my %out = (
        cursor         => defined $cur->{cursor} ? $cur->{cursor} : undef,
        boot_id        => defined $cur->{boot_id} ? $cur->{boot_id} : undef,
        clear_after_us => 0 + $cur->{clear_after_us},
    );
    outl($JSON->encode(\%out));
    return 0;
}

sub cmd_cursor_fields {
    arg_count('cursor-fields', 0, @_);
    begin_storage(0);
    my $cur = load_cursor();
    my $c = defined $cur->{cursor} ? $cur->{cursor} : '';
    my $b = defined $cur->{boot_id} ? $cur->{boot_id} : '';
    outl($c . "\t" . $b . "\t" . (0 + $cur->{clear_after_us}));
    return 0;
}

sub cmd_import {
    my @a = arg_count('import', 1, @_);
    my $file = chars($a[0]);
    my $raw = read_input_file($file, $MAX_IMPORT_BYTES);
    my @raw_lines = split /\n/, $raw, -1;
    pop @raw_lines if @raw_lines && $raw_lines[-1] eq '';
    fail(msgf('err_import_lines', scalar(@raw_lines), $MAX_IMPORT_LINES))
        if @raw_lines > $MAX_IMPORT_LINES;
    begin_storage(1);
    my $cfg = load_settings();
    my $cur = load_cursor();
    my $ourhex = prefix_hex();
    my %seen;
    for my $l (collect_tail_lines('connections', $MAX_IMPORT_LINES)) {
        my $r = eval { $JSONU->decode($l) };
        next unless ref($r) eq 'HASH';
        my $c = $r->{cursor};
        $seen{$c} = 1 if defined $c && !ref $c;
    }
    my @records;
    my ($last_cursor, $last_boot);
    my ($dup, $old) = (0, 0);
    my $lineno = 0;
    for my $line (@raw_lines) {
        $lineno++;
        next if $line =~ /\A\s*\z/;
        my $entry = eval { $JSONU->decode($line) };
        if (!defined $entry) {
            my $e = $@ || 'unknown';
            $e =~ s/\s+\z//;
            fail(msgf('err_import_json', $lineno, describe($e)));
        }
        fail(msgf('err_import_object', $lineno)) unless ref($entry) eq 'HASH';
        my $c = $entry->{__CURSOR};
        fail(msgf('err_import_field', $lineno, '__CURSOR')) unless is_str($c) && is_cursor_ok($c);
        my $b = $entry->{_BOOT_ID};
        fail(msgf('err_import_field', $lineno, '_BOOT_ID'))
            unless is_str($b) && $b =~ /\A[0-9a-f]{32}\z/;
        my $ts = $entry->{__REALTIME_TIMESTAMP};
        fail(msgf('err_import_field', $lineno, '__REALTIME_TIMESTAMP'))
            unless is_str($ts) && $ts =~ /\A[0-9]{1,20}\z/ && $ts > 0;
        $last_cursor = $c;
        $last_boot = $b;
        my $message = $entry->{MESSAGE};
        next unless is_str($message);
        my ($hex, $tag) = $message =~ /\AIPW_([0-9a-f]{10})_([AD]) / ? ($1, $2) : ();
        next unless defined $hex && $hex eq $ourhex;
        my $us = 0 + $ts;
        if ($us <= $cur->{clear_after_us}) { $old++; next }
        if ((defined $cur->{cursor} && $c eq $cur->{cursor}) || $seen{$c}) { $dup++; next }
        my $body = $message;
        $body =~ s/\AIPW_[0-9a-f]{10}_[AD] //;
        my $h = parse_kernel_header($body);
        push @records, {
            type        => 'connection',
            time        => iso_utc($us),
            time_us     => $us,
            decision    => ($tag eq 'A' ? 'allow' : 'deny'),
            src         => $h->{SRC},
            dst         => $h->{DST},
            proto       => $h->{PROTO},
            source_port => $h->{SPT},
            dest_port   => $h->{DPT},
            input       => $h->{IN},
            output      => $h->{OUT},
            message     => bounded(sanitize_human(chars($message)), $MAX_RECORD_CHARS),
            cursor      => $c,
            boot_id     => $b,
        };
        $seen{$c} = 1;
    }
    for my $rec (@records) {
        append_line('connections', $JSON->encode($rec) . "\n");
    }
    if (defined $last_cursor) {
        save_cursor({ cursor => $last_cursor, boot_id => $last_boot, clear_after_us => $cur->{clear_after_us} });
    }
    outl(msgf('msg_import_done', scalar(@records), $dup, $old));
    return 0;
}

sub cmd_view {
    my @a = arg_count('view', 3, @_);
    my $type = check_type($a[0]);
    my $limit = check_limit($a[1]);
    my $format = $a[2];
    fail(msgf('err_bad_format', describe($format)))
        unless defined $format && ($format eq 'json' || $format eq 'text');
    begin_storage(0);
    my $cfg = load_settings();
    my @streams = $type eq 'both' ? ('operations', 'connections') : ($type);
    my @recs;
    for my $s (@streams) {
        expire_archives($s, $cfg);
        my $active = stream_path($s);
        my @lines;
        if (file_ok($active, $MSG{label_file_log})) {
            push @lines, reverse read_tail_lines($active, $limit);
        }
        for (my $n = 1; $n <= $MAX_ARCHIVES && @lines < $limit; $n++) {
            my $p = archive_path($s, $n);
            next unless file_ok($p, $MSG{label_file_archive});
            push @lines, reverse read_tail_lines($p, $limit - @lines);
        }
        @lines = reverse @lines;
        for my $l (@lines) {
            my $path = $active;
            push @recs, parse_record_line($l, $path, $s);
        }
    }
    @recs = sort { $a->{time_us} <=> $b->{time_us} } @recs;
    @recs = @recs[-$limit .. -1] if @recs > $limit;
    if ($format eq 'json') {
        outl($JSON->encode(\@recs));
    } else {
        outl(render_text_record($_)) for @recs;
    }
    return 0;
}

sub cmd_stats_json {
    arg_count('stats-json', 0, @_);
    begin_storage(0);
    my $cfg = load_settings();
    my %streams;
    for my $s (qw(operations connections)) {
        expire_archives($s, $cfg);
        my $active = stream_path($s);
        my ($bytes, $records) = (0, 0);
        if (file_ok($active, $MSG{label_file_log})) {
            my $size = -s $active;
            $bytes = defined $size ? $size : 0;
            $records = count_lines($active);
        }
        my @archives;
        for my $n (1 .. $MAX_ARCHIVES) {
            my $p = archive_path($s, $n);
            next unless file_ok($p, $MSG{label_file_archive});
            my @st = lstat($p);
            push @archives, {
                path  => $p,
                bytes => defined $st[7] ? $st[7] : 0,
                mtime => defined $st[9] ? $st[9] : 0,
            };
        }
        $streams{$s} = {
            path          => $active,
            bytes         => $bytes,
            records       => $records,
            max_bytes     => $cfg->{max_mib} * $MIB,
            auto_rotate   => $cfg->{auto_rotate},
            archive_count => scalar(@archives),
            archives      => \@archives,
        };
    }
    my $cur = load_cursor();
    my %out = (
        logdir        => $LOGDIR,
        settings_file => $SETTINGS_PRESENT ? 1 : 0,
        cursor_file   => $CURSOR_PRESENT ? 1 : 0,
        settings      => $cfg,
        cursor        => {
            cursor         => defined $cur->{cursor} ? $cur->{cursor} : undef,
            boot_id        => defined $cur->{boot_id} ? $cur->{boot_id} : undef,
            clear_after_us => 0 + $cur->{clear_after_us},
        },
        streams       => \%streams,
    );
    outl($JSON->encode(\%out));
    return 0;
}

sub cmd_stats_text {
    arg_count('stats-text', 0, @_);
    begin_storage(0);
    my $cfg = load_settings();
    outl(msgf('msg_stats_logdir', $LOGDIR));
    for my $s (qw(operations connections)) {
        expire_archives($s, $cfg);
        my $active = stream_path($s);
        my ($bytes, $records) = (0, 0);
        if (file_ok($active, $MSG{label_file_log})) {
            my $size = -s $active;
            $bytes = defined $size ? $size : 0;
            $records = count_lines($active);
        }
        my @archives;
        for my $n (1 .. $MAX_ARCHIVES) {
            my $p = archive_path($s, $n);
            next unless file_ok($p, $MSG{label_file_archive});
            my @st = lstat($p);
            push @archives, { path => $p, bytes => (defined $st[7] ? $st[7] : 0) };
        }
        outl(msgf('msg_stats_stream', stream_label($s), $active, $bytes, $records, scalar(@archives)));
        outl(msgf('msg_stats_archive', $_->{path}, $_->{bytes})) for @archives;
    }
    load_cursor();
    outl(msgf('msg_stats_cursor', $CURSOR_PRESENT ? $MSG{msg_stats_cursor_yes} : $MSG{msg_stats_cursor_no}));
    outl($MSG{msg_stats_settings});
    outl($_) for settings_lines($cfg);
    return 0;
}

sub cmd_rotate {
    my @a = arg_count('rotate', 1, @_);
    my $type = check_type($a[0]);
    begin_storage(0);
    my $cfg = load_settings();
    my @streams = $type eq 'both' ? ('operations', 'connections') : ($type);
    for my $s (@streams) {
        my $r = rotate_stream($s, $cfg);
        if ($r eq 'rotated') { outl(msgf('msg_rotate_done', stream_label($s))) }
        elsif ($r eq 'empty') { outl(msgf('msg_rotate_empty', stream_label($s))) }
        else { outl(msgf('msg_rotate_missing', stream_label($s))) }
        expire_archives($s, $cfg);
    }
    return 0;
}

sub cmd_clear {
    my @a = arg_count('clear', 2, @_);
    my $type = check_type($a[0]);
    my $confirm = $a[1];
    fail($MSG{err_bad_confirm}) unless defined $confirm && !ref $confirm && $confirm eq 'CLEAR';
    begin_storage(1);
    my $cfg = load_settings();
    my $cur = load_cursor();
    my @streams = $type eq 'both' ? ('operations', 'connections') : ($type);
    my @skipped;
    for my $s (@streams) {
        my $active = stream_path($s);
        my @st = lstat($active);
        if (@st) {
            if (legal_regular($active)) {
                unlink($active) or fail(msgf('err_file_unlink', $active, $!));
            } else {
                push @skipped, $active;
            }
        }
        for my $n (1 .. $MAX_ARCHIVES) {
            my $p = archive_path($s, $n);
            my @ast = lstat($p);
            next unless @ast;
            if (legal_regular($p)) {
                unlink($p) or fail(msgf('err_file_unlink', $p, $!));
            } else {
                push @skipped, $p;
            }
        }
        if (!-e $active && !-l $active) {
            sysopen(my $fh, $active, O_WRONLY | O_CREAT | O_EXCL | $O_NOFOLLOW, 0600)
                or fail(msgf('err_file_create', $active, $!));
            close $fh or fail(msgf('err_file_write', $active, $!));
            chmod(0600, $active) or fail(msgf('err_file_chmod', $active, $!));
        }
    }
    if ($type eq 'connections' || $type eq 'both') {
        my ($us) = now_micro();
        $cur->{clear_after_us} = $us;
        save_cursor($cur);
    }
    outl(msgf('msg_clear_done', stream_label($type)));
    if ($type ne 'operations') {
        outl(msgf('msg_clear_mark', 0 + $cur->{clear_after_us}));
    }
    warnl(msgf('err_skip_unsafe', $_)) for @skipped;
    return 0;
}

sub cmd_maintain {
    arg_count('maintain', 0, @_);
    begin_storage(0);
    my $cfg = load_settings();
    my $now = int(Time::HiRes::time());
    for my $s (qw(operations connections)) {
        my $active = stream_path($s);
        if (file_ok($active, $MSG{label_file_log})) {
            my @st = lstat($active);
            my $size = defined $st[7] ? $st[7] : 0;
            my $limit = $cfg->{max_mib} * $MIB;
            my $stale = $cfg->{retention_days} > 0
                && $size > 0
                && defined $st[9]
                && $st[9] < $now - $cfg->{retention_days} * 86400;
            if ($size > 0 && (($cfg->{auto_rotate} eq 'on' && $size >= $limit) || $stale)) {
                rotate_stream($s, $cfg);
            }
        }
        expire_archives($s, $cfg);
    }
    return 0;
}

# ------------------------------------------------------------- dispatcher
my %DISPATCH = (
    'prefix'          => \&cmd_prefix,
    'settings-json'   => \&cmd_settings_json,
    'settings-text'   => \&cmd_settings_text,
    'settings-propose' => \&cmd_settings_propose,
    'settings-save'   => \&cmd_settings_save,
    'settings-raw'    => \&cmd_settings_raw,
    'settings-remove' => \&cmd_settings_remove,
    'audit'           => \&cmd_audit,
    'cursor-json'     => \&cmd_cursor_json,
    'cursor-fields'   => \&cmd_cursor_fields,
    'import'          => \&cmd_import,
    'view'            => \&cmd_view,
    'stats-json'      => \&cmd_stats_json,
    'stats-text'      => \&cmd_stats_text,
    'rotate'          => \&cmd_rotate,
    'clear'           => \&cmd_clear,
    'maintain'        => \&cmd_maintain,
);

sub main {
    $LOGDIR = shift @ARGV;
    $CMD = shift @ARGV;
    fail($MSG{err_usage}) unless defined $LOGDIR && length $LOGDIR;
    fail($MSG{err_usage}) unless defined $CMD && length $CMD;
    fail(msgf('err_unknown_command', describe($CMD))) unless exists $DISPATCH{$CMD};
    $LOGDIR = chars($LOGDIR);
    $LOGDIR =~ s{/+\z}{};
    $LOGDIR = '/' if $LOGDIR eq '';
    fail(msgf('err_logdir_absolute', describe($LOGDIR))) unless $LOGDIR =~ m{\A/};
    my $handler = $DISPATCH{$CMD};
    return $handler->(@ARGV);
}

my $rc;
my $ok = eval { $rc = main(); 1 };
if (!$ok) {
    my $e = $@ || 'unknown';
    $e =~ s/\s+\z//;
    errl($MSG{err_prefix} . sprintf($MSG{err_internal}, chars($e)));
    exit 2;
}
exit(defined $rc ? $rc : 0);
PERL
}
# Logging facades and bounded journal collection. No background process is installed.
logging_require() {
    ((EUID==0)) || { error 'root privileges are required'; return 2; }
    [[ -d $DIR && ! -L $DIR ]] || { error "State directory is missing or is not a real directory: $DIR"; return 2; }
    local tool
    for tool in perl sync mktemp rm cat timeout flock; do
        have_tool "$tool" || { error "Logging requires the missing tool: $tool"; return 2; }
    done
    perl -MJSON::PP -MFcntl -MFile::Temp -MCwd -MPOSIX -MTime::HiRes -MDigest::SHA -MFile::Basename -MFile::Spec -MErrno -MB -e 'exit 0' || { error 'Logging requires the full Perl core modules'; return 2; }
}
logging_audit() {
    local action=$1 code=$2 detail=${3:-}
    ((EUID==0)) && have_tool perl || return 0
    if ! log_data audit "$action" "$code" "$detail" > /dev/null; then
        error 'The operation result is final, but its audit log could not be written; check the log directory, permissions and disk space'
    fi
    return 0
}
logging_runtime() {
    local input=${1:-$WORK/log-runtime.json} values
    if (($#==0)); then log_data settings-json > "$input" || return 2; fi
    values=$(perl -MJSON::PP -e 'local $/; open my $h,"<",$ARGV[0] or die "$!\n"; my $s=JSON::PP->new->decode(<$h>); print join("\t",@$s{qw(connections rate burst)}),"\n"' "$input") || return 2
    IFS=$'\t' read -r LOG_MODE LOG_RATE LOG_BURST <<< "$values"
    [[ $LOG_MODE == off || $LOG_MODE == deny || $LOG_MODE == all ]] && [[ $LOG_RATE =~ ^[1-9][0-9]*$ && $LOG_BURST =~ ^[1-9][0-9]*$ ]] && ((LOG_RATE<=100 && LOG_BURST<=100)) || { error 'Invalid runtime logging settings'; return 2; }
    LOG_PREFIX=$(log_data prefix) || return 2
    [[ $LOG_PREFIX =~ ^IPW_[0-9a-f]{10}$ ]] || { error 'Invalid log instance identifier'; return 2; }
}
logging_restore_settings() {
    local file=$1
    if [[ $file == - ]]; then log_data settings-remove > /dev/null; else log_data settings-save "$file" > /dev/null; fi
}
logging_configure() {
    local key=$1 value=$2 rc old_mode
    log_data settings-json > "$WORK/log-old.json" || return 2
    log_data settings-propose "$key" "$value" > "$WORK/log-candidate.json" || return 2
    LOG_CANDIDATE=$WORK/log-candidate.json
    log_data settings-raw > "$WORK/log-before.raw"; rc=$?
    case $rc in 0) LOG_BEFORE=$WORK/log-before.raw ;; 3) LOG_BEFORE=- ;; *) return 2 ;; esac
    logging_runtime "$WORK/log-old.json" || return 2
    old_mode=$LOG_MODE
    logging_runtime "$LOG_CANDIDATE" || return 2
    if [[ $key == connections || ( $key == rate || $key == burst ) && ( $old_mode != off || $LOG_MODE != off ) ]]; then
        require_tools full || return 2
        data load "$STATE" > "$WORK/after" || return 2
        data guard "$WORK/after" || return 2
        install "$WORK/after" 0 || return 2
    else
        LOG_SAVE_PENDING=1
        log_data settings-save "$LOG_CANDIDATE" > /dev/null || return 2
        LOG_SAVE_PENDING=0
    fi
    printf 'Log settings saved.\n'
}
logging_collect() {
    local prefix fields cursor boot clear current rc since help
    local -a args=()
    LOG_SOURCE_STATUS=unavailable
    if ! have_tool journalctl; then error 'Connection log source is unavailable: journalctl was not found; saved records remain readable'; return 0; fi
    help=$(LC_ALL=C journalctl --help 2>&1) || { error 'Connection log source is unavailable: journalctl capability detection failed; saved records remain readable'; return 0; }
    if [[ $help != *--grep* || $help != *--after-cursor* ]]; then error 'Connection log source is unavailable: journalctl lacks filtering or cursor support; saved records remain readable'; return 0; fi
    prefix=$(log_data prefix) || return 2
    fields=$(log_data cursor-json) || return 2
    cursor=$(perl -MJSON::PP -e 'my $s=JSON::PP->new->decode($ARGV[0]); print $s->{cursor}//""' "$fields") || return 2
    boot=$(perl -MJSON::PP -e 'my $s=JSON::PP->new->decode($ARGV[0]); print $s->{boot_id}//""' "$fields") || return 2
    clear=$(perl -MJSON::PP -e 'my $s=JSON::PP->new->decode($ARGV[0]); print $s->{clear_after_us}' "$fields") || return 2
    current=$(tr -d '\n-' < /proc/sys/kernel/random/boot_id) || current=''
    args=(--quiet --no-pager --output=json --lines=+1000 "--grep=^${prefix}_[AD] " _TRANSPORT=kernel)
    if [[ -n $cursor && $boot == "$current" ]]; then args+=("--after-cursor=$cursor")
    elif [[ $clear != 0 ]]; then
        since=$(perl -e 'printf "@%d.%06d", int($ARGV[0]/1000000), $ARGV[0]%1000000' "$clear") || return 2
        args+=("--since=$since")
    fi
    ( ulimit -f 8192; LC_ALL=C timeout --foreground --kill-after=2s 8s journalctl "${args[@]}" ) > "$WORK/journal.jsonl" 2> "$WORK/journal.err"; rc=$?
    # A vacated same-boot cursor can no longer be used. Replay is deduplicated by the engine.
    if ((rc!=0)) && [[ -n $cursor && -s $WORK/journal.err ]]; then
        args=(--quiet --no-pager --output=json --lines=+1000 "--grep=^${prefix}_[AD] " _TRANSPORT=kernel)
        if [[ $clear != 0 ]]; then
            since=$(perl -e 'printf "@%d.%06d", int($ARGV[0]/1000000), $ARGV[0]%1000000' "$clear") || return 2
            args+=("--since=$since")
        fi
        ( ulimit -f 8192; LC_ALL=C timeout --foreground --kill-after=2s 8s journalctl "${args[@]}" ) > "$WORK/journal.jsonl" 2> "$WORK/journal.err"; rc=$?
    fi
    if ((rc==1)) && [[ ! -s $WORK/journal.jsonl && ! -s $WORK/journal.err ]]; then rc=0; fi
    if ((rc!=0)) || [[ -s $WORK/journal.err ]]; then
        error 'Connection log source is temporarily unreadable; saved records remain readable'
        [[ ! -s $WORK/journal.err ]] || cat -- "$WORK/journal.err" >&2
        return 0
    fi
    LOG_SOURCE_STATUS=available
    [[ -s $WORK/journal.jsonl ]] || return 0
    log_data import "$WORK/journal.jsonl" > /dev/null || return 2
}
logging_cli() {
    local cmd=$1 type=both lines=50 format=text status=0 confirm='' key='' value='' option
    shift
    if [[ $cmd == log-settings && ${1:-} == --set ]]; then
        (($#==3)) || { error 'log-settings --set requires a setting key and value'; return 2; }
        cli _logging-config "$2" "$3"; return $?
    fi
    while (($#)); do
        option=$1; shift
        case $option in
            --json) [[ $cmd == logs || $cmd == log-settings ]] || { error 'This log command does not accept --json'; return 2; }; format=json ;;
            --status) [[ $cmd == logs ]] || { error 'This log command does not accept --status'; return 2; }; status=1 ;;
            --type) [[ $cmd == logs || $cmd == log-rotate || $cmd == log-clear ]] && (($#)) || { error 'This log command does not accept --type or its value is missing'; return 2; }; type=$1; shift ;;
            --lines) [[ $cmd == logs ]] && (($#)) || { error 'This log command does not accept --lines or its value is missing'; return 2; }; lines=$1; shift ;;
            --confirm) [[ $cmd == log-clear ]] && (($#)) || { error 'This log command does not accept --confirm or its value is missing'; return 2; }; confirm=$1; shift ;;
            -h|--help) usage; return 0 ;;
            *) error "Unknown logging option: $option"; return 2 ;;
        esac
    done
    [[ $type == operations || $type == connections || $type == both ]] || { error 'Log type must be operations, connections or both'; return 2; }
    [[ $lines =~ ^[0-9]{1,4}$ ]] && ((10#$lines>=1 && 10#$lines<=1000)) || { error 'Log line count must be an integer from 1 to 1000'; return 2; }
    [[ $cmd != log-clear || $confirm == CLEAR ]] || { error 'Log clearing requires --confirm CLEAR'; return 2; }
    WORK='' TRANSACTION=0 RECOVERY_KEEP=0 LOG_SAVE_PENDING=0 AUDIT_ACTION=''
    trap cleanup EXIT
    trap 'printf "\nOperation interrupted\n" >&2; exit 130' INT TERM
    logging_require || return 2
    WORK=$(mktemp -d "$DIR/.ip-port-allowlist-work.XXXXXXXX") || { error 'Could not create a temporary logging directory'; return 2; }
    case $cmd in
        logs)
            if ((status)) || [[ $type != operations ]]; then logging_collect || return 2; fi
            log_data maintain || return 2
            if ((status)); then
                if [[ $format == json ]]; then
                    log_data stats-json > "$WORK/log-status.json" || return 2
                    perl -MJSON::PP -e 'local $/; open my $h,"<",$ARGV[0] or die "$!\n"; my $j=JSON::PP->new->canonical; my $s=$j->decode(<$h>); $s->{source_status}=$ARGV[1]; print $j->encode($s),"\n"' "$WORK/log-status.json" "${LOG_SOURCE_STATUS:-unavailable}"
                else
                    log_data stats-text || return 2
                    printf 'Connection log source: %s (collected on view, sampled packets with a rate limit)\n' "${LOG_SOURCE_STATUS:-unavailable}"
                fi
            else log_data view "$type" "$lines" "$format"; fi ;;
        log-settings) log_data "settings-$format" ;;
        log-rotate) AUDIT_ACTION=log-rotate; log_data rotate "$type" ;;
        log-clear)
            # Audit a successful clear before deleting operations, keeping the selected stream empty.
            if [[ $type == connections ]]; then AUDIT_ACTION=log-clear; else logging_audit log-clear 0 "type=$type"; fi
            log_data clear "$type" "$confirm" ;;
        log-maintain) AUDIT_ACTION=log-maintain; log_data maintain ;;
    esac
}
logging_status() { menu_cli logs --status; }
logging_show_settings() { menu_cli log-settings; }
logging_view() { menu_cli logs --type "$1" --lines "$2"; }
logging_set() { menu_cli log-settings --set "$1" "$2"; }
logging_rotate() { menu_cli log-rotate --type "$1"; }
logging_clear() { menu_cli log-clear --type "$1" --confirm "$2"; }

state_token() { data token "$1" | sha256sum | awk '{print $1}'; }
have_tool() { command -v "$1" >/dev/null 2>&1; }
have_firewall() { have_tool "${1##*/}"; }
tool_capable() {
    local help
    case $1 in
        timeout) help=$(LC_ALL=C timeout --help 2>&1) && [[ $help == *--foreground* && $help == *--kill-after* ]] ;;
        sync) help=$(LC_ALL=C sync --help 2>&1) && [[ $help == *--file-system* ]] ;;
        mv) help=$(LC_ALL=C mv --help 2>&1) && [[ $help == *--no-target-directory* ]] ;;
        ip) help=$(ip -j address show scope global 2>&1) && [[ $help =~ ^[[:space:]]*\[ ]] ;;
        *) return 0 ;;
    esac
}
perl_probe() {
    perl -Mstrict -Mwarnings -Mutf8 -MJSON::PP -MSocket=AF_INET,AF_INET6,inet_pton -MEncode=decode -MB -e '
        binmode STDOUT, ":encoding(UTF-8)" or die "UTF-8 stdout: $!";
        binmode STDERR, ":encoding(UTF-8)" or die "UTF-8 stderr: $!";
        open my $h, "<:encoding(UTF-8)", "/dev/null" or die "UTF-8 input: $!";
        close $h or die "Close input: $!";
        my $s=decode("UTF-8", "probe");
        die "B string flags" unless B::svref_2object(\$s)->FLAGS & B::SVp_POK();
        die "JSON codec" unless JSON::PP->new->decode(JSON::PP->new->encode({ok=>1}))->{ok};
        die "IPv4 parser" unless defined inet_pton(AF_INET,"127.0.0.1");
        die "IPv6 parser" unless defined inet_pton(AF_INET6,"::1");
    '
}
dependency_scan() {
    local verbose=${1:-0} scope=${2:-full} tool package details bad=0
    local -A missing=()
    MISSING_PACKAGES=()
    for tool in perl awk flock timeout mktemp cat chmod mv rm sync od tr wc grep sha256sum stat mkdir ip; do
        if ! have_tool "$tool" || ! tool_capable "$tool"; then
            case $tool in perl) package=perl ;; awk) package='awk' ;; flock) package=util-linux ;; grep) package='grep' ;; ip) package=iproute2 ;; *) package=coreutils ;; esac
            missing[$package]=1; bad=1
            ((verbose==0)) || printf 'Missing tool or required capability: %s (provided by %s)\n' "$tool" "$package" >&2
        fi
    done
    if have_tool perl; then
        if ! details=$(perl_probe 2>&1); then
            missing[perl]=1; bad=1
            if ((verbose)); then printf 'Perl core modules or UTF-8 encoding support are incomplete; a full perl is required, perl-base is not enough.\n%s\n' "$details" >&2; fi
        fi
    fi
    if [[ $scope == full ]]; then
        for tool in /usr/sbin/iptables /usr/sbin/ip6tables /usr/sbin/iptables-restore /usr/sbin/ip6tables-restore /usr/sbin/iptables-save /usr/sbin/ip6tables-save; do
            if ! have_firewall "$tool"; then
                missing[iptables]=1; bad=1
                ((verbose==0)) || printf 'Missing firewall tool: %s (package iptables)\n' "$tool" >&2
            fi
        done
    fi
    for package in perl iptables util-linux coreutils awk grep iproute2; do [[ ! ${missing[$package]+x} ]] || MISSING_PACKAGES+=("$package"); done
    ((bad==0))
}
require_tools() {
    if ! dependency_scan 0 "${1:-full}"; then
        dependency_scan 1 "${1:-full}" || :
        error 'Dependencies are incomplete, operation stopped. Choose menu 9, or run doctor / doctor --install.'
        return 2
    fi
}
package_manager() {
    local manager
    for manager in apt-get dnf yum apk; do if have_tool "$manager"; then printf '%s\n' "$manager"; return 0; fi; done
    return 1
}
map_packages() {
    local manager=$1 group package
    shift
    INSTALL_PACKAGES=()
    for group in "$@"; do
        package=$group
        case $manager:$group in
            apt-get:awk) package=mawk ;;
            dnf:awk|yum:awk) package=gawk ;;
            dnf:iproute2|yum:iproute2) package=iproute ;;
            dnf:perl|yum:perl) package=perl-core ;;
            apk:util-linux) package=flock ;;
            apk:awk) package=gawk ;;
        esac
        INSTALL_PACKAGES+=("$package")
    done
}
install_packages() {
    local manager=$1
    shift
    case $manager in
        apt-get) apt-get install --yes --no-install-recommends --no-upgrade "$@" ;;
        dnf) dnf install --assumeyes --setopt=install_weak_deps=False "$@" ;;
        yum) yum install --assumeyes "$@" ;;
        apk) apk add "$@" ;;
        *) return 2 ;;
    esac
}
doctor() {
    local install=0 answer rc manager
    if (($#)); then [[ $# == 1 && $1 == --install ]] || { error 'Usage: doctor [--install]'; return 2; }; install=1; fi
    if dependency_scan 1 full; then printf 'Dependency check passed; nothing to install.\n'; return 0; fi
    if ((install==0)); then error 'Dependency check failed. Choose menu 9, or run doctor --install.'; return 2; fi
    if ! manager=$(package_manager); then
        error 'No supported package manager found (apt-get/dnf/yum/apk); install the missing dependencies manually:'
        printf '  %s\n' "${MISSING_PACKAGES[@]}" >&2
        return 2
    fi
    ((EUID==0)) || { error 'Installing dependencies requires root; run doctor --install as root or with sudo'; return 2; }
    map_packages "$manager" "${MISSING_PACKAGES[@]}"
    printf 'Package manager: %s\nMissing packages to install: %s\n' "$manager" "${INSTALL_PACKAGES[*]}"
    printf 'Installs dependencies only; it does not modify firewall rules, configuration or scheduled tasks. Type yes to confirm installation: '
    if ! IFS= read -r answer || [[ $answer != yes ]]; then printf '\nCancelled, nothing was installed.\n'; return 0; fi
    rc=0
    install_packages "$manager" "${INSTALL_PACKAGES[@]}" || rc=2
    if dependency_scan 1 full; then
        if ((rc)); then error 'The install command failed; even though the dependency check now passes, check the package manager errors'; return 2; fi
        printf 'Installation complete, dependency check passed.\n'
        return 0
    fi
    error 'Installation failed or dependencies are still incomplete; check the package manager errors and PATH, then retry.'
    return 2
}
run() { timeout --foreground --kill-after=5 30 "$@" || { error "Command failed or timed out: $1"; return 2; }; }
firewall() {
    local tool=iptables
    [[ $1 == 4 ]] || tool=ip6tables
    command -v "$tool${2:-}" || { error "Firewall command not found: $tool${2:-}"; return 2; }
}
apply_text() {
    local f=$1 file=$2 mode=${3:-commit} tool
    tool=$(firewall "$f" -restore) || return 2
    local -a args=("$tool" --noflush -w 10)
    [[ $mode == test ]] && args+=(--test)
    run "${args[@]}" < "$file"
}
atomic_save() {
    local source=$1 target=$2 temporary
    temporary=$(mktemp "$DIR/.ip-port-allowlist-write.XXXXXXXX") || return 2
    if ! cat -- "$source" > "$temporary" || ! chmod 600 "$temporary" || ! sync -f "$temporary" || ! mv -fT -- "$temporary" "$target" || ! sync -f "$DIR"; then
        rm -f -- "$temporary"; error "Atomic save failed: $target"; return 2
    fi
}
durable_remove() { rm -f -- "$1" && sync -f "$DIR"; }

# Finite-state shlex-compatible lexer for iptables -S; never execute rule text.
lex_rule() {
    local input=$1 token='' mode=plain c next started=0 i length=${#1}
    TOKENS=()
    for ((i=0;i<length;i++)); do
        c=${input:i:1}
        case $mode in
            single) if [[ $c == "'" ]]; then mode=plain; else token+=$c; fi ;;
            double)
                if [[ $c == '"' ]]; then mode=plain
                elif [[ $c == "\\" ]]; then
                    ((i+=1)); ((i<length)) || return 2; next=${input:i:1}
                    if [[ $next == "\\" || $next == '"' || $next == "'" || $next == '$' || $next == '`' ]]; then token+=$next; else token+="\\$next"; fi
                else token+=$c; fi ;;
            plain)
                case $c in
                    " "|$'\t') if ((started)); then TOKENS+=("$token"); token=''; started=0; fi ;;
                    "'") mode=single; started=1 ;;
                    '"') mode=double; started=1 ;;
                    "\\") ((i+=1)); ((i<length)) || return 2; token+=${input:i:1}; started=1 ;;
                    *) token+=$c; started=1 ;;
                esac ;;
        esac
    done
    [[ $mode == plain ]] || return 2
    ((started)) && TOKENS+=("$token")
    return 0
}
restore_line() {
    local arg quoted='' sep=''
    for arg in "$@"; do
        [[ $arg != *$'\n'* && $arg != *$'\r'* ]] || return 2
        if [[ $arg =~ ^[A-Za-z0-9_./:!+\-]+$ ]]; then quoted=$arg
        else quoted=${arg//\\/\\\\}; quoted=${quoted//\"/\\\"}; quoted="\"$quoted\""; fi
        printf '%s%s' "$sep" "$quoted"; sep=' '
    done
    printf '\n'
}
snapshot() {
    local f=$1 output=$2 tool line target pos=0 i chain found
    local raw=$WORK/raw.$f records=$WORK/records.$f
    local -a chains=() TOKENS=()
    tool=$(firewall "$f") || return 2
    run "$tool" -w 10 -t raw -S > "$raw" || return 2
    : > "$records" || return 2
    while IFS= read -r line; do
        lex_rule "$line" || { error 'Cannot parse the firewall rules'; return 2; }
        if [[ ${TOKENS[0]:-} == -N && ${TOKENS[1]:-} =~ ^IPW_[0-9a-f]{10}$ ]]; then
            chains+=("${TOKENS[1]}")
            data args chain "${TOKENS[1]}" | tr -d '\n' >> "$records" || return 2
            printf '\n' >> "$records"
        fi
    done < "$raw"
    while IFS= read -r line; do
        lex_rule "$line" || return 2
        [[ ${TOKENS[0]:-} == -A ]] || continue
        [[ ${TOKENS[1]:-} == PREROUTING ]] && ((pos+=1))
        found=0; for chain in "${chains[@]}"; do [[ ${TOKENS[1]:-} == "$chain" ]] && found=1; done
        if ((found)); then data args rule "${TOKENS[@]}" | tr -d '\n' >> "$records" || return 2; printf '\n' >> "$records"; fi
        for ((i=2;i<${#TOKENS[@]}-1;i++)); do
            if [[ ${TOKENS[i]} == -j || ${TOKENS[i]} == -g ]]; then
                target=${TOKENS[i+1]}
                [[ $target =~ ^IPW_[0-9a-f]{10}$ ]] || continue
                [[ ${TOKENS[1]} == PREROUTING ]] || { error "Managed chain $target is referenced by another chain; refusing to modify it"; return 2; }
                found=0; for chain in "${chains[@]}"; do [[ $target == "$chain" ]] && found=1; done
                ((found)) || { error "Managed chain $target is missing its definition"; return 2; }
                data args hook "$pos" "${TOKENS[@]:2}" | tr -d '\n' >> "$records" || return 2
                printf '\n' >> "$records"
            fi
        done
    done < "$raw"
    data snapshot-pack "$records" > "$output"
}
unpack_snapshot() { data snapshot-unpack "$1" > "$2"; }
removal_lines() {
    local input=$1 kind count n arg
    local -a args=() chains=()
    while IFS= read -r -d '' kind && IFS= read -r -d '' count; do
        args=(); for ((n=0;n<count;n++)); do IFS= read -r -d '' arg || return 2; args+=("$arg"); done
        case $kind in
            chain) chains+=("${args[0]}") ;;
            hook) restore_line -D PREROUTING "${args[@]:1}" || return 2 ;;
        esac
    done < "$input"
    for n in "${chains[@]}"; do restore_line -F "$n" || return 2; done
    for n in "${chains[@]}"; do restore_line -X "$n" || return 2; done
}
update_plan() {
    local state=$1 f=$2 previous=$3 output=$4 chain kind proto port source
    local lines=$WORK/state-lines.$f unpack=$WORK/unpack.$f
    data state-lines "$state" "$f" > "$lines" || return 2
    unpack_snapshot "$previous" "$unpack" || return 2
    printf '*raw\n' > "$output" || return 2
    if [[ -s $lines ]]; then
        chain=IPW_$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n') || return 2
        [[ $chain =~ ^IPW_[0-9a-f]{10}$ ]] || return 2
        restore_line -N "$chain" >> "$output" || return 2
        while IFS=$'\t' read -r kind proto port source; do
            case $kind in
                allow)
                    if [[ $LOG_MODE == all ]]; then restore_line -A "$chain" -p "$proto" --dport "$port" -s "$source" -m limit --limit "$LOG_RATE/minute" --limit-burst "$LOG_BURST" -j LOG --log-prefix "${LOG_PREFIX}_A " --log-level 6 >> "$output" || return 2; fi
                    restore_line -A "$chain" -p "$proto" --dport "$port" -s "$source" -j RETURN >> "$output" || return 2 ;;
                deny)
                    if [[ $LOG_MODE != off ]]; then restore_line -A "$chain" -p "$proto" --dport "$port" -m limit --limit "$LOG_RATE/minute" --limit-burst "$LOG_BURST" -j LOG --log-prefix "${LOG_PREFIX}_D " --log-level 6 >> "$output" || return 2; fi
                    restore_line -A "$chain" -p "$proto" --dport "$port" -j DROP >> "$output" || return 2 ;;
                hook) restore_line -I PREROUTING 1 '!' -i lo -d "$port" -p "$proto" -j "$chain" >> "$output" || return 2 ;;
            esac
        done < "$lines"
    fi
    removal_lines "$unpack" >> "$output" || return 2
    printf 'COMMIT\n' >> "$output"
}
rollback_plan() {
    local current=$1 previous=$2 output=$3 kind count n arg
    local -a args=()
    unpack_snapshot "$current" "$WORK/current.nul" || return 2
    unpack_snapshot "$previous" "$WORK/previous.nul" || return 2
    printf '*raw\n' > "$output" || return 2
    removal_lines "$WORK/current.nul" >> "$output" || return 2
    while IFS= read -r -d '' kind && IFS= read -r -d '' count; do
        args=(); for ((n=0;n<count;n++)); do IFS= read -r -d '' arg || return 2; args+=("$arg"); done
        case $kind in
            chain) restore_line -N "${args[0]}" >> "$output" || return 2 ;;
            rule) restore_line "${args[@]}" >> "$output" || return 2 ;;
            hook) restore_line -I PREROUTING "${args[@]}" >> "$output" || return 2 ;;
        esac
    done < "$WORK/previous.nul"
    printf 'COMMIT\n' >> "$output"
}
recover_pending() {
    local journal=${1:-$JOURNAL}
    [[ -e $journal ]] || return 0
    local f failures=0 rc saved=$WORK/recovery-journal
    cat -- "$journal" > "$saved" || return 2
    data journal-families "$saved" > "$WORK/recover-families" || return 2
    while IFS= read -r f; do
        if ! data journal-snapshot "$saved" "$f" > "$WORK/recover-prev.$f" || ! snapshot "$f" "$WORK/recover-current.$f" || ! rollback_plan "$WORK/recover-current.$f" "$WORK/recover-prev.$f" "$WORK/rollback.$f" || ! apply_text "$f" "$WORK/rollback.$f"; then failures=1; fi
    done < "$WORK/recover-families"
    if ((failures)); then error 'Rule rollback did not finish; the recovery record was kept'; return 2; fi
    data journal-state "$saved" > "$WORK/recover-state"; rc=$?
    case $rc in
        0) atomic_save "$WORK/recover-state" "$STATE" || return 2 ;;
        3) durable_remove "$STATE" || return 2 ;;
        *) return 2 ;;
    esac
    data journal-log-settings "$saved" > "$WORK/recover-log-settings"; rc=$?
    case $rc in
        0) logging_restore_settings "$WORK/recover-log-settings" || return 2 ;;
        3) : ;;
        4) logging_restore_settings - || return 2 ;;
        *) return 2 ;;
    esac
    if ! durable_remove "$JOURNAL"; then
        atomic_save "$saved" "$JOURNAL" || :
        if [[ ! -e $JOURNAL ]]; then cat -- "$saved" > "$JOURNAL" && chmod 600 "$JOURNAL" || :; fi
        RECOVERY_KEEP=1
        error "Removing the recovery record was not made durable; the backup is kept at $saved"
        return 2
    fi
    printf 'Rolled back the previous unfinished update\n' >&2
}
cleanup() {
    local rc=$? source=$JOURNAL
    trap - EXIT
    trap '' INT TERM
    if ((TRANSACTION)); then
        if [[ ! -e $source && -f $WORK/new-journal ]]; then source=$WORK/new-journal; fi
        if [[ -e $source ]]; then
            if ! recover_pending "$source"; then
                RECOVERY_KEEP=1
                if [[ ! -e $JOURNAL ]]; then atomic_save "$source" "$JOURNAL" || :; fi
                error "The update failed and the rollback did not finish; recovery material is kept in $WORK, run recover"
                ((rc==130)) || rc=2
            fi
        else
            RECOVERY_KEEP=1; error "The recovery record is missing; temporary material is kept in $WORK"; ((rc==130)) || rc=2
        fi
    fi
    if ((LOG_SAVE_PENDING)); then
        if ! logging_restore_settings "$LOG_BEFORE"; then
            RECOVERY_KEEP=1; error "Logging settings rollback failed; previous settings are retained in $WORK"; rc=2
        fi
        LOG_SAVE_PENDING=0
    fi
    [[ -z $AUDIT_ACTION ]] || logging_audit "$AUDIT_ACTION" "$rc" "$AUDIT_DETAIL"
    if [[ -n $WORK ]] && ((RECOVERY_KEEP==0)); then rm -rf -- "$WORK"; fi
    exit "$rc"
}
install() {
    local state=$1 dry=$2 f p4='' p6=''
    local -a plans=()
    if [[ -n $LOG_CANDIDATE ]]; then logging_runtime "$LOG_CANDIDATE" || return 2
    else logging_runtime || return 2; fi
    for f in 4 6; do
        snapshot "$f" "$WORK/previous.$f" || return 2
        update_plan "$state" "$f" "$WORK/previous.$f" "$WORK/plan.$f" || return 2
        if [[ $(wc -l < "$WORK/plan.$f") -gt 2 ]]; then plans+=("$f"); fi
    done
    # Prevalidate every family BEFORE writing the journal or changing any rules.
    for f in "${plans[@]}"; do apply_text "$f" "$WORK/plan.$f" test || return 2; done
    if ((dry)); then for f in "${plans[@]}"; do printf '# IPv%s (dry run passed, not committed)\n' "$f"; cat -- "$WORK/plan.$f"; done; return 0; fi
    for f in "${plans[@]}"; do if [[ $f == 4 ]]; then p4=$WORK/previous.4; else p6=$WORK/previous.6; fi; done
    data journal-make "$STATE" "$p4" "$p6" "$LOG_BEFORE" > "$WORK/new-journal" || return 2
    TRANSACTION=1
    atomic_save "$WORK/new-journal" "$JOURNAL" || return 2
    for f in "${plans[@]}"; do apply_text "$f" "$WORK/plan.$f" || return 2; done
    atomic_save "$state" "$STATE" || return 2
    if [[ -n $LOG_CANDIDATE ]]; then log_data settings-save "$LOG_CANDIDATE" > /dev/null || return 2; fi
    durable_remove "$JOURNAL" || return 2
    TRANSACTION=0
}
show_live() {
    local f tool chain line
    for f in 4 6; do
        snapshot "$f" "$WORK/live.$f" || return 2
        printf '\nIPv%s live managed rules:\n' "$f"
        awk '/^-N IPW_[0-9a-f]+$/ {print; next} /^-A / && /(^|[[:space:]])IPW_[0-9a-f]+([[:space:]]|$)/ {print}' "$WORK/raw.$f"
        if grep -q '^-N IPW_' "$WORK/raw.$f"; then
            tool=$(firewall "$f" -save) || return 2
            run "$tool" -c -t raw > "$WORK/counters.$f" || return 2
            printf 'Counters:\n'
            while IFS= read -r line; do
                if [[ $line =~ ^-N\ (IPW_[0-9a-f]{10})$ ]]; then
                    chain=${BASH_REMATCH[1]}; awk -v c="$chain" 'index($0,c) {print}' "$WORK/counters.$f"
                fi
            done < "$WORK/raw.$f"
        else printf 'No managed chains\n'; fi
    done
}
save_counters() {
    local f=$1 tool
    tool=$(firewall "$f" -save) || return 2
    run "$tool" -c -t raw > "$WORK/save.$f"
}
# show --live --json: structured snapshot of the kernel's managed chains for external monitoring.
show_live_json() {
    local f
    for f in 4 6; do
        rm -f "$WORK/save.$f"
        save_counters "$f" || rm -f "$WORK/save.$f"
    done
    data live-json "$WORK/save.4" "$WORK/save.6" || return 2
}
usage() {
    cat <<'HELP'
Usage: ip-port-allowlist.sh [command] [options]; run without arguments to start the menu.
  validate/set --ips IP[,CIDR] --ports PORT[,PORT] [--proto tcp|udp|both]
               [--family auto|4|6|both]
  edit --ips SOURCES --ports PORTS [--proto PROTOCOLS]
       [--new-ips SOURCES] [--new-ports PORTS]
  remove --ports PORTS [--family 4|6|both] [--proto PROTOCOLS]
  block --ports PORTS [--family 4|6|both] [--proto PROTOCOLS]
  targets --family 4|6 --ips HOST[,HOST] (only /32 or /128)
  clear --all
  show [--json|--live|--live --json]
  restore
  recover
  repair-state [--from-live|--empty|--backup-only] [--dry-run] (guided repair when the state file is corrupt)
  doctor [--install] (check only; --install requires typing yes)
  logs [--type operations|connections|both] [--lines 1..1000] [--json|--status]
  log-settings [--json] | log-settings --set KEY VALUE
  log-rotate [--type operations|connections|both]
  log-clear [--type operations|connections|both] --confirm CLEAR
  log-maintain
Connection logging is off by default; when enabled it samples matching packets with a rate limit and collects records on view.
Logs are stored only in .ip-port-allowlist.logs under the state directory; clearing does not delete the system journal.
set/remove/block default protocol is TCP/UDP; set defaults to address family auto; remove/block default to IPv4+IPv6.
Modifying commands and restore support --dry-run; modifying commands support --expect-state SHA256.
IP_PORT_ALLOWLIST_DIR defaults to /root; the path may contain spaces. Requires Bash 4.4+ and full Perl core modules.
A missing/legacy configuration detects targets automatically from non-lo scope global addresses (including NAT private and bridge addresses).
An address family without global addresses has no targets; configure targets with targets before setting rules for that family.
Menu 9 / doctor --install supports apt-get, dnf, yum and apk when present; on unknown systems install manually.
--live --json prints structured live rules (managed chains, rules, hooks and counters) for external monitoring.
repair-state is only for an unparseable state file; by default it only backs up (--backup-only); rebuilding the state requires typing yes.
HELP
}
cli() {
    case ${1:-} in logs|log-settings|log-rotate|log-clear|log-maintain) logging_cli "$@"; return $? ;; esac
    if [[ ${1:-} == doctor ]]; then
        trap - EXIT
        trap 'printf "\nOperation interrupted\n" >&2; exit 130' INT TERM
        shift; doctor "$@"; local doctor_rc=$?; logging_audit doctor "$doctor_rc" ''; return "$doctor_rc"
    fi
    WORK='' TRANSACTION=0 RECOVERY_KEEP=0 AUTO_ADDRESSES='' LOG_CANDIDATE='' LOG_BEFORE='' LOG_SAVE_PENDING=0 AUDIT_ACTION='' AUDIT_DETAIL=''
    trap cleanup EXIT
    trap 'printf "\nOperation interrupted\n" >&2; exit 130' INT TERM
    local cmd=${1:-} ips='' ports='' proto='' family='' ni='' np='' expect='' repair='' dry=0 all=0 json=0 live=0 option val token
    local have_ips=0 have_ports=0 have_proto=0 have_family=0 have_ni=0 have_np=0 have_expect=0
    [[ $cmd == -h || $cmd == --help ]] && { usage; exit 0; }
    local log_key='' log_value=''
    case $cmd in validate|set|edit|remove|block|clear|show|restore|recover|targets|repair-state|_logging-config) ;; *) die "Unknown command: $cmd" ;; esac
    shift
    if [[ $cmd == _logging-config ]]; then
        (($#==2)) || die 'Logging settings require a setting key and value'
        log_key=$1 log_value=$2; shift 2; AUDIT_ACTION=log-settings
    elif [[ $cmd != show && $cmd != validate ]]; then AUDIT_ACTION=$cmd; fi
    while (($#)); do
        option=$1; shift
        case $option in
            -h|--help) usage; exit 0 ;;
            --ips|--ports|--proto|--family|--new-ips|--new-ports|--expect-state)
                (($#)) || die "$option is missing its value"; val=$1; shift
                case $option in
                    --ips) ips=$val; have_ips=1 ;; --ports) ports=$val; have_ports=1 ;;
                    --proto) proto=$val; have_proto=1 ;; --family) family=$val; have_family=1 ;;
                    --new-ips) ni=$val; have_ni=1 ;; --new-ports) np=$val; have_np=1 ;;
                    --expect-state) expect=$val; have_expect=1 ;;
                esac ;;
            --dry-run) dry=1 ;; --all) all=1 ;; --json) json=1 ;; --live) live=1 ;;
            --from-live) repair=from-live ;; --empty) repair=empty ;; --backup-only) repair=backup-only ;;
            *) die "Unknown option: $option" ;;
        esac
    done
    case $cmd in
        validate|set) ((have_ips && have_ports)) || die '--ips and --ports are required'; [[ -n $ips && -n $ports ]] || die 'The allowlist and ports must not be empty'; ((have_proto)) || proto=tcp,udp; ((have_family)) || family=auto ;;
        remove|block) ((have_ports)) || die '--ports is required'; [[ -n $ports ]] || die 'Ports must not be empty'; ((have_ips==0)) || die 'This command does not accept --ips'; if [[ $cmd == block ]]; then ((have_proto)) || proto=tcp,udp; ((have_family)) || family=both; else ((have_proto)) || proto=tcp,udp; ((have_family)) || family=both; fi ;;
        targets) ((have_ips && have_family)) || die 'targets requires --ips and --family'; ((have_ports==0 && have_proto==0)) || die 'targets does not accept ports or protocols'; [[ -n $ips && ( $family == 4 || $family == 6 ) ]] || die 'targets address family must be 4 or 6, and the target must not be empty' ;;
        edit) ((have_ips && have_ports)) || die '--ips and --ports are required'; [[ -n $ips && -n $ports ]] || die 'Sources and ports must not be empty'; ((have_proto || have_ni || have_np)) || die 'Specify at least one of --proto, --new-ips or --new-ports'; ((have_family==0)) || die 'edit does not accept --family' ;;
        clear) ((all)) || die 'clear requires --all' ;;
        repair-state) [[ -n $repair ]] || repair=backup-only ;;
    esac
    [[ $cmd == edit ]] || ((have_ni==0 && have_np==0)) || die 'This command does not accept --new-ips/--new-ports'
    [[ $cmd == clear ]] || ((all==0)) || die 'This command does not accept --all'
    [[ $cmd == show ]] || ((json==0 && live==0)) || die 'This command does not accept --json/--live'
    [[ $cmd == repair-state ]] || [[ -z $repair ]] || die 'This command does not accept --from-live/--empty/--backup-only'
    if [[ $cmd == repair-state ]]; then
        ((have_ips==0 && have_ports==0 && have_proto==0 && have_family==0 && have_ni==0 && have_np==0 && have_expect==0 && all==0 && json==0 && live==0)) || die 'repair-state does not accept source/port/protocol/family/new-value/expected-state/--all/--json/--live'
    fi
    if [[ $cmd == show || $cmd == recover || $cmd == restore || $cmd == clear ]]; then ((have_ips==0 && have_ports==0 && have_proto==0 && have_family==0)) || die 'This command does not accept source/port/protocol/family options'; fi
    if [[ $cmd == show || $cmd == recover || $cmd == validate ]]; then ((dry==0 && have_expect==0)) || die 'This command does not accept --dry-run/--expect-state'; fi
    [[ $cmd != restore ]] || ((have_expect==0)) || die 'restore does not accept --expect-state'
    ((have_proto==0)) || [[ -n $proto ]] || die 'Protocol must not be empty'
    ((have_ni==0)) || [[ -n $ni ]] || die 'New sources must not be empty'
    ((have_np==0)) || [[ -n $np ]] || die 'New ports must not be empty'
    case $cmd in
        set|validate) [[ $family == auto || $family == 4 || $family == 6 || $family == both ]] || die 'Invalid address family' ;;
        remove|block) [[ $family == 4 || $family == 6 || $family == both ]] || die 'Invalid address family' ;;
    esac
    if [[ $cmd == validate ]]; then require_tools core || exit 2; data validate "$ips" "$ports" "$proto" "$family" || exit 2; exit 0; fi
    if [[ $cmd == _logging-config || $cmd == repair-state && $repair == backup-only ]]; then require_tools core || exit 2; else require_tools full || exit 2; fi
    AUDIT_DETAIL="dry_run=$dry"
    ((EUID==0)) || die 'root privileges are required'
    [[ -d $DIR ]] || die "State directory does not exist: $DIR"
    local namespace globaldir=/run/ip-port-allowlist
    namespace=$(stat -Lc '%i' /proc/self/ns/net) || die 'Cannot read the network namespace id'
    [[ $namespace =~ ^[0-9]+$ && ! -L $globaldir ]] || die 'Invalid shared lock directory or network namespace'
    if ! mkdir -p -- "$globaldir" || ! chmod 700 "$globaldir"; then die 'Cannot create the shared firewall lock directory'; fi
    exec 8>> "$globaldir/net.$namespace.lock" || die 'Cannot open the shared firewall lock'
    chmod 600 "$globaldir/net.$namespace.lock" || die 'Cannot set the shared lock permissions'
    flock -x 8 || die 'Cannot acquire the shared firewall lock'
    exec 9>> "$LOCK" || die 'Cannot open the lock file'
    chmod 600 "$LOCK" || die 'Cannot set the lock file permissions'
    flock -x 9 || die 'Cannot acquire the configuration lock'
    WORK=$(mktemp -d "$DIR/.ip-port-allowlist-work.XXXXXXXX") || die 'Cannot create the temporary directory'
    if [[ $cmd == show ]] || ((dry)); then [[ ! -e $JOURNAL ]] || die 'An unfinished rule update exists; run recover first; viewing/dry-run is paused'
    else recover_pending || exit 2; fi
    [[ $cmd != recover ]] || { printf 'Recovery check complete\n'; exit 0; }
    if [[ $cmd == _logging-config ]]; then logging_configure "$log_key" "$log_value" || exit 2; exit 0; fi
    if [[ $cmd == repair-state ]]; then
        repair_state "$repair" "$dry" || exit 2
        exit 0
    fi
    data load "$STATE" > "$WORK/before" || exit 2
    if ((have_expect)); then token=$(state_token "$WORK/before") || exit 2; [[ $token == "$expect" ]] || die 'The configuration was modified by another session; nothing was committed, select and preview again'; fi
    if [[ $cmd == show ]]; then
        if ((live && json)); then show_live_json || exit 2
        elif ((live)); then show_live || exit 2
        elif ((json)); then cat -- "$WORK/before"
        else data show "$WORK/before" || exit 2; fi
        exit 0
    fi
    data transform "$WORK/before" "$cmd" "$ips" "$ports" "$proto" "$family" "$ni" "$np" > "$WORK/after" || exit 2
    if [[ $cmd == edit ]]; then
        data changes "$WORK/before" "$WORK/after" > "$WORK/changes"; val=$?
        if ((val==3)); then printf 'The configuration did not change; nothing to save.\n'; exit 0; elif ((val)); then exit 2; fi
    fi
    if [[ $cmd == targets ]]; then
        data target-impact "$WORK/before" "$WORK/after" > "$WORK/impact"; val=$?
        if ((val==3)); then printf 'Target host addresses did not change; nothing to save.\n'; exit 0; elif ((val)); then exit 2; fi
        cat -- "$WORK/impact"
    fi
    data guard "$WORK/after" || exit 2
    install "$WORK/after" "$dry" || exit 2
    if ((dry==0)); then styled 'Rules updated and saved' '1;32'; data show "$WORK/after" || exit 2; fi
}

# Menu commands are isolated; the menu PID forwards cancellation and waits for rollback.
menu_interrupt() {
    trap '' INT TERM
    if [[ -n ${MENU_CHILD:-} ]]; then kill -TERM "$MENU_CHILD" 2>/dev/null || :; wait "$MENU_CHILD" || :; fi
    printf '\nOperation interrupted\n' >&2
    exit 130
}
menu_cli() {
    local rc
    ( cli "$@" ) <&0 &
    MENU_CHILD=$!
    wait "$MENU_CHILD"; rc=$?
    MENU_CHILD=''
    return "$rc"
}
# Confirmation always goes through cli under lock with a canonical state token.
menu_rule() {
    local width=${COLUMNS:-76} line
    [[ $width =~ ^[0-9]{1,3}$ ]] || width=76
    ((width>=32)) || width=32
    ((width<=76)) || width=76
    printf -v line '%*s' "$((width-4))" ''
    if ((UNI)); then styled "  ${line// /─}" '2;37'; else styled "  ${line// /-}" '2;37'; fi
}
menu_section() {
    local mark='*'; ((UNI==0)) || mark='◆'
    printf '\n'
    if ((COLOR)); then printf '  \033[36m%s\033[0m \033[1;37m%s\033[0m\n' "$mark" "$1"; else printf '  %s %s\n' "$mark" "$1"; fi
}
menu_option() {
    local key=$1 label=$2 tone=${3:-36} hint=${4:-} dot='-'
    ((UNI==0)) || dot='·'
    if ((COLOR)); then
        printf '   \033[%sm[%s]\033[0m  %s' "$tone" "$key" "$label"
        [[ -z $hint ]] || printf '  \033[2;37m%s %s\033[0m' "$dot" "$hint"
    else
        printf '   [%s]  %s' "$key" "$label"
        [[ -z $hint ]] || printf '  %s %s' "$dot" "$hint"
    fi
    printf '\n'
}
panel_width() {
    local columns=${COLUMNS:-100}
    [[ $columns =~ ^[0-9]{1,5}$ ]] || columns=100
    columns=$((10#$columns-4))
    ((columns>=36)) || columns=36
    ((columns<=108)) || columns=108
    printf '%s\n' "$columns"
}
clear_page() {
    if [[ -t 0 && -t 1 && ${TERM:-dumb} != dumb ]]; then printf '\033[2J\033[H'; else printf '\n'; fi
}
panel_render() {
    local AUTO_ADDRESSES=${AUTO_ADDRESSES:-'[]'}
    have_tool perl || return 2
    data panel "$@"
}
page() {
    clear_page
    local subtitle="Main menu › $1"
    [[ -z ${2:-} ]] || subtitle+='    /    Enter 0 or q to return to the main menu at any time'
    if ! panel_render title "$1" "$(panel_width)" "$COLOR" "$UNI" "$subtitle" '' 0 2>/dev/null; then
        menu_rule;styled "  | $1" '1;36'
        [[ -z ${2:-} ]] || styled '    Type 0 or q at any time to return to the main menu' '2;37'
        menu_rule;printf '\n'
    fi
}
render_main_menu() {
    clear_page
    local state=''
    [[ -z ${MENUWORK:-} ]] || state=$MENUWORK/before
    if panel_render menu "$state" "$(panel_width)" "$COLOR" "$UNI" "$NOTICE" "$STATUS" "$broken" 2>/dev/null; then return 0; fi
    page 'IP / Port allowlist manager'
    [[ -z $NOTICE ]] || styled "  $NOTICE" 33
    [[ -z $STATUS ]] || error "$STATUS"
    menu_section 'Actions'
    menu_option 1 'View allowlist / block rules'; menu_option 2 'Set / Replace allowlist'
    menu_option 3 'Edit existing allowlist'; menu_option 4 'Remove restrictions from given ports'
    menu_option 5 'Clear all restrictions' 31; menu_option 6 'View live firewall rules'
    menu_option 7 'Block ports (deny all sources)' 31
    menu_option 8 'Set target host addresses'; menu_option 9 'Check / install dependencies'
    menu_option 10 'Logs'; menu_option 11 'Log rotation and clear settings'
    ((broken==0)) || menu_option R 'Repair the corrupt state file' 31
    menu_option 0 'Quit' '2;37';printf '\n'
}
entry() {
    local prompt=$1 default=${2:-}
    printf '%s' "$prompt"
    if ! IFS= read -r REPLY; then return 11; fi
    REPLY=${REPLY#"${REPLY%%[![:space:]]*}"}; REPLY=${REPLY%"${REPLY##*[![:space:]]}"}
    case ${REPLY,,} in q|b|0) return 10 ;; esac
    [[ -n $REPLY ]] || REPLY=$default
}
# State-file diagnosis and guided repair. The corrupt file is always backed up byte-for-byte first.
state_diagnose() {
    local f tool out size sum
    printf '  State file: %s\n' "$STATE"
    if [[ ! -e $STATE ]]; then
        printf '  File does not exist; it is created automatically on the first save.\n'
    else
        size=$(wc -c < "$STATE") || return 2
        sum=$(sha256sum -- "$STATE") || return 2
        printf '  Size: %s bytes; SHA256: %s\n' "$size" "${sum%% *}"
    fi
    [[ ! -e $JOURNAL ]] || printf '  Note: an unfinished rule update exists; recover runs first before the repair.\n'
    for f in 4 6; do
        if tool=$(firewall "$f" -save) && out=$(run "$tool" -t raw); then
            printf '  Kernel IPv%s: %s managed chains, %s rules, %s hooks\n' "$f" \
                "$(grep -c '^:IPW_[0-9a-f]\{10\} ' <<< "$out")" \
                "$(grep -c '^-A IPW_[0-9a-f]\{10\} ' <<< "$out")" \
                "$(grep -cE '(^|[[:space:]])(-j|-g) IPW_[0-9a-f]{10}([[:space:]]|$)' <<< "$out")"
        else
            printf '  Kernel IPv%s: cannot read live rules\n' "$f"
        fi
    done
}
state_backup() {
    local stamp target n=0
    [[ -e $STATE ]] || { error "State file does not exist: $STATE"; return 2; }
    stamp=$(date -u +%Y%m%dT%H%M%SZ) || return 2
    target=$STATE.corrupt.$stamp
    while [[ -e $target ]]; do ((n+=1)); target=$STATE.corrupt.$stamp.$n; done
    if ! cp -- "$STATE" "$target" || ! chmod 600 "$target" || ! sync -f "$target" || ! sync -f "$DIR"; then
        rm -f -- "$target"; error "Failed to back up the corrupt state file: $target"; return 2
    fi
    printf '%s\n' "$target"
}
repair_rebuild() {
    local mode=$1 output=$2
    AUTO_ADDRESSES=''
    if [[ $mode == empty ]]; then data load "$WORK/no-state-file" > "$output" || return 2; return 0; fi
    snapshot 4 "$WORK/repair.4" || return 2
    snapshot 6 "$WORK/repair.6" || return 2
    data state-from-snapshot "$WORK/repair.4" "$WORK/repair.6" > "$output"
}
repair_state() {
    local mode=$1 dry=$2 answer backup reason f tool out
    state_diagnose || return 2
    if [[ ! -e $STATE ]]; then printf 'The state file does not exist; nothing to repair.\n'; return 0; fi
    if data load "$STATE" > "$WORK/healthy" 2> "$WORK/load.err"; then printf 'The state file is healthy; nothing to repair.\n'; return 0; fi
    reason=$(tr -d '\n' < "$WORK/load.err")
    printf 'Cannot read the state file: %s\n' "${reason:-unknown error}" >&2
    case $mode in backup-only|empty|from-live) ;; *) error "Unknown repair mode: $mode"; return 2 ;; esac
    if [[ $mode != backup-only ]]; then repair_rebuild "$mode" "$WORK/repaired" || return 2; fi
    if ((dry)); then
        printf '# Dry run: state file not modified; mode=%s\n' "$mode"
        [[ $mode == backup-only ]] || { data show "$WORK/repaired" || return 2; }
        return 0
    fi
    if [[ $mode != backup-only ]]; then
        printf 'The repair backs up the corrupt file first and then writes the new state. Type yes to confirm: '
        if ! IFS= read -r answer || [[ $answer != yes ]]; then printf '\nCancelled, the state file was not modified.\n'; return 0; fi
    fi
    backup=$(state_backup) || return 2
    printf 'Corrupt file backed up: %s\n' "$backup"
    [[ $mode != backup-only ]] || return 0
    atomic_save "$WORK/repaired" "$STATE" || return 2
    printf 'State file rebuilt: %s\n' "$STATE"
    data show "$STATE" || return 2
    if [[ $mode == empty ]]; then
        for f in 4 6; do
            tool=$(firewall "$f" -save) || continue
            out=$(run "$tool" -t raw 2>/dev/null) || continue
            grep -q '^:IPW_[0-9a-f]\{10\} ' <<< "$out" || continue
            printf 'Note: state was rebuilt as empty but the kernel still has managed rules for IPv%s; run restore if you want them to match.\n' "$f"
        done
    fi
}
repair_menu() {
    state_diagnose || return 2
    printf '\n'
    menu_option 1 'Rebuild state from live kernel rules' '' 'Restore from the current firewall rules; requires typing yes'
    menu_option 2 'Rebuild as empty state' '' 'Auto-detect target addresses, no rules; requires typing yes'
    menu_option 3 'Back up the corrupt file only' '' 'Leave the state file untouched, repair manually later'
    printf '\n'; menu_rule
    menu_option 0 'Return to the main menu' '2;37'
    printf '\n'
    while :; do
        entry '  Select [0-3]: ' || return $?
        case $REPLY in
            1) menu_cli repair-state --from-live || return $?; NOTICE='State file handling complete.'; return 10 ;;
            2) menu_cli repair-state --empty || return $?; NOTICE='State file handling complete.'; return 10 ;;
            3) menu_cli repair-state --backup-only || return $?; NOTICE='The corrupt state file was backed up.'; return 10 ;;
            0) return 10 ;;
            *) error 'Enter 0-3' ;;
        esac
    done
}
menu_state() {
    [[ ! -e $JOURNAL ]] || { error 'An unfinished rule update exists; run recover first'; return 2; }
    AUTO_ADDRESSES=''
    data load "$STATE" > "$MENUWORK/before"
}
# ask PROMPT CHECK ARGS...: reprompt until "data CHECK ARGS... VALUE" passes; empty is rejected. ask_optional allows empty.
ask() {
    local prompt=$1; shift
    while :; do
        entry "$prompt" || return $?
        [[ -n $REPLY ]] || { error 'must not be empty'; continue; }
        data "$@" "$REPLY" > /dev/null && return 0
    done
}
ask_optional() {
    local prompt=$1; shift
    while :; do
        entry "$prompt" || return $?
        [[ -n $REPLY ]] && ! data "$@" "$REPLY" > /dev/null || return 0
    done
}
read_protocol() {
    local default=${1:-} value dl=''
    case $default in 1) dl='1 = TCP' ;; 2) dl='2 = UDP' ;; 3) dl='3 = TCP/UDP' ;; esac
    printf '  Protocol\n'
    menu_option 1 'TCP'; menu_option 2 'UDP'; menu_option 3 'TCP/UDP'
    while :; do
        if [[ -n $default ]]; then entry "  Select protocol [default $dl]: " "$default" || return $?
        else entry '  Select protocol [1-3; Enter keeps the current protocol]: ' || return $?; fi
        value=$REPLY; case $value in 1) value=tcp ;; 2) value=udp ;; 3) value=tcp,udp ;; esac
        if [[ -z $value ]]; then REPLY=''; return 0; fi
        if value=$(data protos "$value"); then REPLY=$value; return 0; fi
    done
}
# mode "available": 1 IPv4 / 2 IPv6 / 3 both, only families that have target hosts
# mode "target": 1 IPv4 / 2 IPv6, used when configuring target hosts. REPLY = 4 | 6 | both
choose_family() {
    local mode=$1 value default='' a4=0 a6=0 family dl=''
    if [[ $mode == available ]]; then
        data families "$MENUWORK/before" > "$MENUWORK/families" || return 2
        while IFS= read -r value; do [[ $value != 4 ]] || a4=1; [[ $value != 6 ]] || a6=1; done < "$MENUWORK/families"
        ((a4 || a6)) || { error 'No target host address is configured yet; set one with menu 8 first'; return 2; }
        if ((a4 && a6)); then default=3; elif ((a4)); then default=1; else default=2; fi
    fi
    case $default in 1) dl='1 = IPv4' ;; 2) dl='2 = IPv6' ;; 3) dl='3 = IPv4 + IPv6' ;; esac
    printf '  Address family\n'
    menu_option 1 'IPv4'; menu_option 2 'IPv6'
    [[ $mode != available ]] || menu_option 3 'IPv4 + IPv6'
    while :; do
        if [[ -n $default ]]; then entry "  Select address family [default $dl]: " "$default" || return $?
        else entry '  Select address family [1-2]: ' || return $?; fi
        case $REPLY in
            1) family=4 ;;
            2) family=6 ;;
            3) [[ $mode == available ]] && family=both || { error 'Enter 1 or 2'; continue; } ;;
            *) error 'Enter a valid item number'; continue ;;
        esac
        if [[ $mode == available ]]; then
            if [[ $family == 4 || $family == both ]] && ((a4==0)); then error 'IPv4 has no target host address, so port restrictions cannot be set; choose another address family, or configure one with menu 8 first'; continue; fi
            if [[ $family == 6 || $family == both ]] && ((a6==0)); then error 'IPv6 has no target host address, so port restrictions cannot be set; choose another address family, or configure one with menu 8 first'; continue; fi
        fi
        REPLY=$family; return 0
    done
}
choose_many() {
    local count=$1
    while :; do
        entry '  Items [1,3 / 1-3 / all; 0 to go back]: ' || return $?
        if data selection "$REPLY" "$count" > "$MENUWORK/selection"; then mapfile -t SELECTED < "$MENUWORK/selection"; return 0; fi
    done
}
confirm_change() {
    local token rc impact=0
    page 'Change preview · confirm save' back
    data transform "$MENUWORK/before" "$@" > "$MENUWORK/after" || return 2
    data changes "$MENUWORK/before" "$MENUWORK/after"; rc=$?
    if ((rc==3)); then NOTICE='The configuration did not change; nothing to save.'; return 10; elif ((rc)); then return 2; fi
    # Target changes are always reported with their impact on existing allow rules (exit 3 = no target change).
    data target-impact "$MENUWORK/before" "$MENUWORK/after" || impact=$?
    ((impact==0 || impact==3)) || return 2
    data guard "$MENUWORK/after" || return 2
    entry '  Type y to save; anything else cancels: ' || return $?
    if [[ ${REPLY,,} != y ]]; then NOTICE='Cancelled, rules were not modified.'; return 10; fi
    token=$(state_token "$MENUWORK/before") || return 2
    menu_cli "${SUBMIT[@]}" --expect-state "$token"
}
set_menu() {
    local ips ports proto
    menu_state || return 2
    printf '  IPv4 / IPv6 sources may be mixed; entering only IPv4 does not modify IPv6.\n'
    printf '  The existing source list of the same port is replaced as a whole; to append only, use "Edit existing allowlist".\n\n'
    ask '  Allowed IPs/IP ranges (separate with commas or spaces): ' check-sources "$MENUWORK/before" || return $?; ips=$REPLY
    ask '  Restricted ports (separate with commas or spaces): ' check-ports || return $?; ports=$REPLY
    read_protocol 3 || return $?; proto=$REPLY
    SUBMIT=(set --ips "$ips" --ports "$ports" --proto "$proto")
    confirm_change set "$ips" "$ports" "$proto" auto '' ''
}
ports_menu() {
    local cmd=$1 ports family proto
    menu_state || return 2
    data show "$MENUWORK/before" || return 2
    if [[ $cmd == block ]]; then
        printf '  Denies all sources for the selected address family, protocols and ports; it affects configured targets only.\n'
        ask '  Ports to block: ' check-ports || return $?; ports=$REPLY
    else
        ask '  Ports whose restrictions to remove: ' check-ports || return $?; ports=$REPLY
    fi
    choose_family available || return $?; family=$REPLY
    read_protocol 3 || return $?; proto=$REPLY
    SUBMIT=("$cmd" --ports "$ports" --family "$family" --proto "$proto")
    confirm_change "$cmd" '' "$ports" "$proto" "$family" '' ''
}
edit_menu() {
    local source label i sources='' ports='' action proto='' ni='' np=''
    local -a source_options=() port_options=() SELECTED=()
    menu_state || return 2
    data rows "$MENUWORK/before" > "$MENUWORK/rows" || return 2
    i=0
    while IFS=$'\t' read -r source label; do source_options+=("$source"); ((i+=1)); printf '  [%s]  %s → %s\n' "$i" "$source" "$label"; done < "$MENUWORK/rows"
    ((i)) || { NOTICE='There are no rules to edit; use "Set / Replace allowlist" first.'; return 10; }
    choose_many "$i" || return $?
    for i in "${SELECTED[@]}"; do sources+=${sources:+,}${source_options[i]}; done
    data available "$MENUWORK/before" "$sources" > "$MENUWORK/ports" || return 2
    page 'Edit allowlist · select ports' back; i=0
    while IFS=$'\t' read -r source label; do port_options+=("$source"); ((i+=1)); printf '  [%s]  %s(%s)\n' "$i" "$source" "$label"; done < "$MENUWORK/ports"
    choose_many "$i" || return $?
    for i in "${SELECTED[@]}"; do ports+=${ports:+,}${port_options[i]}; done
    sources=$(data filter-sources "$MENUWORK/before" "$sources" "$ports") || return 2
    page 'Edit allowlist · change content' back
    printf '  Sources: %s\n  Ports: %s\n\n' "$sources" "$ports"
    menu_option 1 'Change protocol'; menu_option 2 'Change source IPs / IP ranges'; menu_option 3 'Change ports'; menu_option 4 'Combined edit'
    while :; do entry '  Select [1-4; 0 to go back]: ' || return $?; action=$REPLY; [[ $action =~ ^[1-4]$ ]] && break; done
    printf '  Enter keeps the current value; unselected IPs and ports stay unchanged.\n'
    if [[ $action == 1 || $action == 4 ]]; then read_protocol || return $?; proto=$REPLY; fi
    if [[ $action == 2 || $action == 4 ]]; then ask_optional '  New source IPs/IP ranges (multiple allowed): ' check-sources "$MENUWORK/before" || return $?; ni=$REPLY; fi
    if [[ $action == 3 || $action == 4 ]]; then ask_optional '  New ports (multiple allowed): ' check-ports || return $?; np=$REPLY; fi
    [[ -n $proto || -n $ni || -n $np ]] || { NOTICE='The configuration did not change; nothing to save.'; return 10; }
    SUBMIT=(edit --ips "$sources" --ports "$ports")
    [[ -z $proto ]] || SUBMIT+=(--proto "$proto")
    [[ -z $ni ]] || SUBMIT+=(--new-ips "$ni")
    [[ -z $np ]] || SUBMIT+=(--new-ports "$np")
    confirm_change edit "$sources" "$ports" "$proto" '' "$ni" "$np"
}
clear_menu() {
    local token
    menu_state || return 2
    data show "$MENUWORK/before" || return 2
    styled '  WARNING: this clears every IPv4/IPv6 TCP/UDP restriction; the ports may become open to the public internet.' 31
    entry '  Type CLEAR to confirm clearing: ' || return $?
    if [[ $REPLY == CLEAR ]]; then token=$(state_token "$MENUWORK/before") || return 2; menu_cli clear --all --expect-state "$token"; else NOTICE='Cancelled, rules were not modified.'; return 10; fi
}
targets_menu() {
    local family ips
    menu_state || return 2
    data show "$MENUWORK/before" || return 2
    printf '  Auto-detected targets include every non-lo global address of this host (including Docker bridges such as 172.17.0.1);\n'
    printf '  If you only need to protect specific addresses, specify them here manually; the input replaces all targets of the chosen address family.\n\n'
    choose_family target || return $?; family=$REPLY
    ask '  New target host addresses (separate multiple values with commas or spaces; /32 or /128 only): ' check-hosts "$family" || return $?; ips=$REPLY
    SUBMIT=(targets --family "$family" --ips "$ips")
    confirm_change targets "$ips" '' '' "$family" '' ''
}
# Logging pages. Backend: logging_status, logging_show_settings, logging_view TYPE LINES, logging_set KEY VALUE, logging_rotate TYPE, logging_clear TYPE CLEAR; 0 = ok, 2 = failed.
log_read() {
    printf '%s' "$1"
    if ! IFS= read -r REPLY; then return 11; fi
    REPLY=${REPLY#"${REPLY%%[![:space:]]*}"}; REPLY=${REPLY%"${REPLY##*[![:space:]]}"}
}
log_pause() {
    [[ -t 0 && -t 1 ]] || return 0
    printf '\n  Press Enter to continue…'; IFS= read -r REPLY || return 11
}
log_confirm() {
    local rc=0
    entry "$1" || rc=$?
    ((rc==0)) || return "$rc"
    [[ ${REPLY,,} == y ]] || return 10
}
# log_int PROMPT MIN MAX [DEFAULT]: strict integer. Empty keeps DEFAULT or cancels (10); 0 cancels unless MIN is 0.
log_int() {
    local prompt=$1 min=$2 max=$3 default=${4-}
    while :; do
        log_read "$prompt" || return $?
        if [[ -z $REPLY ]]; then
            if [[ -n $default ]]; then REPLY=$default; return 0; fi
            return 10
        fi
        if [[ ${REPLY,,} == q ]]; then return 10; fi
        if [[ $REPLY == 0 ]] && ((min>0)); then return 10; fi
        if [[ $REPLY =~ ^[0-9]{1,4}$ ]] && ((10#$REPLY>=min && 10#$REPLY<=max)); then REPLY=$((10#$REPLY)); return 0; fi
        error "Enter an integer in the range $min-$max"
    done
}
# log_word PROMPT HINT WORD...: exact lowercase choice. Empty input or 0 cancels (10).
log_word() {
    local prompt=$1 hint=$2 word
    shift 2
    while :; do
        log_read "$prompt" || return $?
        if [[ -z $REPLY || $REPLY == 0 || ${REPLY,,} == q ]]; then return 10; fi
        for word in "$@"; do [[ $REPLY == "$word" ]] && return 0; done
        error "Allowed values: $hint"
    done
}
log_apply() {
    local key=$1 value=$2 note=${3-}
    printf '  Setting %s to %s\n' "$key" "$value"
    [[ -z $note ]] || styled "  $note" 33
    log_confirm '  Type y to save; anything else cancels: ' || return $?
    if logging_set "$key" "$value"; then LOG_NOTICE='Log settings saved.'; return 0; fi
    LOG_NOTICE='Failed to save log settings; see the error above.'
    return 2
}
log_rotate() {
    printf '  Rotating %s now. This applies only to logs for this script and does not affect the kernel journal.\n' "$1"
    log_confirm '  Enter y to rotate; any other input cancels:' || return $?
    if logging_rotate "$1"; then LOG_NOTICE='Rotation completed.'; return 0; fi
    LOG_NOTICE='Rotation failed; see the error above.'
    return 2
}
log_clear() {
    styled "  Warning: this clears $1 logs for this script and does not delete global kernel journal entries." 31
    entry '  Type CLEAR to confirm; any other input cancels:' || return $?
    if [[ $REPLY != CLEAR ]]; then LOG_NOTICE='CLEAR was not entered; logs were not cleared.'; return 10; fi
    if logging_clear "$1" CLEAR; then LOG_NOTICE='Logs for this script were cleared.'; return 0; fi
    LOG_NOTICE='Clear failed; see the error above.'
    return 2
}
log_show() {
    page "$3" back
    logging_view "$1" "$2" || error 'Log read failed; see the backend error above'
    log_pause
}
logs_menu() {
    local lines=50 rc=0
    while :; do
        page 'Logs' back
        menu_section 'Current status'
        logging_status || error 'Could not read log status; see the backend error above'
        styled '  Note: connections log is a rate-limited packet sample matched by rules of this script; it does not guarantee every connection. RETURN means the source matched rules of this script, not that the packet is finally accepted by later filter chains. Collection is triggered on view; no background daemon.' 33
        menu_section 'View and settings'
        menu_option 1 'View operations log'; menu_option 2 'View connections log'
        menu_option 3 'View operations and connections logs'; menu_option 4 'Set number of lines'
        menu_option 0 'Return to the main menu' '2;37'; printf '\n'
        printf '  Current number of lines: %s (default 50)\n' "$lines"
        while :; do
            entry '  Select [0-4]:' || return $?
            case $REPLY in 1|2|3|4) break ;; *) error 'Enter 0-4' ;; esac
        done
        case $REPLY in
            1) log_show operations "$lines" 'View operations log' ;;
            2) log_show connections "$lines" 'View connections log' ;;
            3) log_show both "$lines" 'View operations and connections logs' ;;
            4) log_int '  Number of lines [1-1000; Enter keeps current, 0 cancels]:' 1 1000 "$lines" && lines=$REPLY ;;
        esac
        rc=$?
        ((rc!=11)) || return 11
    done
}
log_settings_menu() {
    local rc=0 LOG_NOTICE=''
    while :; do
        page 'Log rotation and clear settings' back
        [[ -z $LOG_NOTICE ]] || styled "  $LOG_NOTICE" 33
        LOG_NOTICE=''
        logging_show_settings || error 'Could not read log settings; see the backend error above'
        styled '  Note: connections log is a rate-limited sample as above; collection is triggered on view, no background daemon.' 33
        printf '  Defaults (reference only; the actual values above apply): operations on, connections off, 10 MiB, keep 5, 30 days, rate 10 per minute, burst 5, auto rotation on\n'
        menu_section 'Log settings'
        menu_option 1 'Operations log switch (on/off)'; menu_option 2 'Connections log mode (off/deny/all)'
        menu_option 3 'Maximum size per file (MiB, 1-100)'; menu_option 4 'Files to keep (1-20)'
        menu_option 5 'Retention days (0-365)'; menu_option 6 'Connections log rate limit (per minute, 1-100)'
        menu_option 7 'Connections log burst (1-100)'; menu_option 8 'Automatic rotation (on/off)'
        menu_section 'Rotate and clear'
        menu_option 9 'Rotate now'; menu_option 10 'Clear logs for this script' 31
        menu_option 0 'Return to the main menu' '2;37'; printf '\n'
        while :; do
            entry '  Select [0-10]:' || return $?
            case $REPLY in 1|2|3|4|5|6|7|8|9|10) break ;; *) error 'Enter 0-10' ;; esac
        done
        case $REPLY in
            1) log_word '  New value [on/off; Enter or 0 cancels]:' 'on/off' on off && log_apply operations "$REPLY" ;;
            2) log_word '  New mode [off/deny/all; Enter or 0 cancels]:' 'off/deny/all' off deny all && log_apply connections "$REPLY" 'Changing the connections log mode rebuilds the managed chain. It only adds LOG rules and does not change accept or reject decisions. This page does not run the rebuild; the backend result decides when it takes effect.' ;;
            3) log_int '  New value [1-100 MiB; Enter or 0 cancels]:' 1 100 && log_apply max_mib "$REPLY" ;;
            4) log_int '  New value [1-20 files; Enter or 0 cancels]:' 1 20 && log_apply keep "$REPLY" ;;
            5) log_int '  New value [0-365 days; Enter cancels, 0 is valid]:' 0 365 && log_apply retention_days "$REPLY" ;;
            6) log_int '  New value [1-100 per minute; Enter or 0 cancels]:' 1 100 && log_apply rate "$REPLY" ;;
            7) log_int '  New value [1-100; Enter or 0 cancels]:' 1 100 && log_apply burst "$REPLY" ;;
            8) log_word '  New value [on/off; Enter or 0 cancels]:' 'on/off' on off && log_apply auto_rotate "$REPLY" ;;
            9) log_word '  Log to rotate [operations/connections/both; Enter or 0 cancels]:' 'operations/connections/both' operations connections both && log_rotate "$REPLY" ;;
            10) log_word '  Log to clear [operations/connections/both; Enter or 0 cancels]:' 'operations/connections/both' operations connections both && log_clear "$REPLY" ;;
        esac
        rc=$?
        ((rc!=11)) || return 11
        case $rc in
            0|2) log_pause || return 11 ;;
            10) [[ -n $LOG_NOTICE ]] || LOG_NOTICE='Cancelled; nothing was changed.' ;;
        esac
    done
}
menu() {
    ((EUID==0)) || die 'root privileges are required'
    local MENUWORK='' MENU_CHILD='' choice rc REPLY ready broken NOTICE='' STATUS=''
    local -a SUBMIT=()
    trap '[[ -z $MENUWORK ]] || rm -rf -- "$MENUWORK"' EXIT
    trap menu_interrupt INT TERM
    while :; do
        ready=0
        broken=0
        STATUS=''
        if dependency_scan 0 full; then
            if [[ -z $MENUWORK ]]; then
                if [[ ! -d $DIR ]]; then STATUS="State directory does not exist: $DIR"
                elif ! MENUWORK=$(mktemp -d "$DIR/.ip-port-allowlist-menu.XXXXXXXX"); then STATUS='Cannot create the menu temporary directory'
                else ready=1; fi
            else ready=1; fi
        else STATUS='Dependencies are incomplete, port policy operations stopped. Choose 9 to check/install dependencies.'; fi
        if [[ -e $JOURNAL ]]; then
            STATUS='An unfinished rule update exists; run recover first'
        elif ((ready)); then
            if ! menu_state 2> "$MENUWORK/read-error"; then
                broken=1
                STATUS="State file is corrupt: $STATE; choose R for guided repair"
                [[ ! -s $MENUWORK/read-error ]] || STATUS+=$'\n'"$(cat -- "$MENUWORK/read-error")"
            fi
        fi
        render_main_menu
        NOTICE=''
        local keys='[0-11]'
        ((broken==0)) || keys='[0-11 / R]'
        printf '  Select %s: ' "$keys"
        IFS= read -r choice || exit 0
        [[ $choice != 0 ]] || exit 0
        if ((broken)) && [[ $choice =~ ^[1-8]$ ]]; then error 'The state file is corrupt, this operation cannot run; choose R to repair the state file'; continue; fi
        if [[ $choice =~ ^[1-8]$ ]] && ((ready==0)); then error 'Operation stopped; first complete the dependency check via menu 9 and make sure the state directory exists'; continue; fi
        rc=0
        case $choice in
            1) page 'View port policy'; menu_cli show || rc=$? ;;
            2) page 'Set / Replace allowlist' back; set_menu || rc=$? ;;
            3) page 'Edit existing allowlist' back; edit_menu || rc=$? ;;
            4) page 'Remove restrictions from given ports' back; ports_menu remove || rc=$? ;;
            5) page 'Clear all restrictions' back; clear_menu || rc=$? ;;
            6) page 'Live firewall rules'; menu_cli show --live || rc=$? ;;
            7) page 'Block ports · deny all sources' back; ports_menu block || rc=$? ;;
            8) page 'Set target host addresses' back; targets_menu || rc=$? ;;
            9) page 'Check / install dependencies'; menu_cli doctor --install || rc=$? ;;
            R|r) if ((broken)); then page 'Corrupt state file · guided repair' back; repair_menu || rc=$?; else styled '  Enter 0-11' 33; fi ;;
            10) logs_menu || rc=$? ;;
            11) log_settings_menu || rc=$? ;;
            *) if ((broken)); then styled '  Enter 0-11, or R to repair the state file' 33; else styled '  Enter 0-11' 33; fi ;;
        esac
        ((rc!=11)) || exit 0
        ((rc!=10)) || continue
        ((rc!=130)) || exit 130
        printf '\n  Press Enter to return to the main menu…'; IFS= read -r REPLY || exit 0
    done
}
trap 'printf "\nOperation interrupted\n" >&2; exit 130' INT TERM
if (($#)); then cli "$@"; else menu; fi
