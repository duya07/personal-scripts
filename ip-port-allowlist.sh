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
error() { printf '错误：%s\n' "$*" >&2; }
die() { error "$*"; exit 2; }
((BASH_VERSINFO[0]>4 || (BASH_VERSINFO[0]==4 && BASH_VERSINFO[1]>=4))) || die '需要 Bash 4.4 或更新版本，请先安装 Bash 并用 bash 运行本脚本'
styled() { if ((COLOR)); then printf '\033[%sm%s\033[0m\n' "$2" "$1"; else printf '%s\n' "$1"; fi; }
data() {
    if [[ -z $AUTO_ADDRESSES ]]; then
        AUTO_ADDRESSES=$(ip -j address show scope global) || { error '无法检测本机目标地址，请检查 ip -j address show scope global'; return 2; }
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
sub text { my($p)=@_; open my $h,'<:encoding(UTF-8)',$p or fail("无法读取 $p：$!"); local $/; my $s=<$h>; close $h or fail("无法关闭 $p：$!"); defined($s)?$s:'' }
sub readjson { $json->decode(text($_[0])) }
sub emit { print $json->pretty->encode($_[0]); $json->pretty(0) }
sub str { !ref($_[0]) && defined($_[0]) && (B::svref_2object(\$_[0])->FLAGS & B::SVp_POK()) }
sub obj { ref($_[0]) eq 'HASH' }
sub arr { ref($_[0]) eq 'ARRAY' }
sub keysare { my($h,@k)=@_; obj($h) && join(',',sort keys %$h) eq join(',',sort @k) }
sub parts { grep {length} split /[\s,]+/, $_[0] }
sub ipv4bytes { my($s)=@_; my @a=split /\./,$s,-1; fail("无效的 IPv4 地址：$s") unless @a==4 && !grep {!/\A(?:0|[1-9][0-9]{0,2})\z/ || $_>255} @a; pack('C4',@a) }
sub ipnet {
    my($s)=@_; fail('IP 必须是字符串') unless str($s);
    my @v=split m{/},$s,-1; fail("无效的 IP 或网段：$s") if @v>2 || $v[0]=~/[%\s]/;
    my($addr,$pre)=@v; my $f=index($addr,':')>=0?6:4; my $bits=$f==4?32:128; my $packed;
    if($f==4){$packed=ipv4bytes($addr)}else{if($addr=~/([^:]+\.[^:]+)\z/){ipv4bytes($1)} $packed=inet_pton(AF_INET6,$addr); fail("无效的 IPv6 地址：$s") unless defined $packed}
    if(!defined $pre){$pre=$bits}
    elsif($f==4 && $pre=~/\./){my $mask=unpack('B32',ipv4bytes($pre)); $mask=~tr/01/10/ if $mask=~/\A0/ && $mask ne '0'x32; fail("无效的子网掩码：$s") unless $mask=~/\A(1*)(0*)\z/; $pre=length($1)}
    else{fail("无效的前缀长度：$s") unless $pre=~/\A[0-9]+\z/ && $pre<=$bits; $pre=0+$pre}
    my $binary=unpack('B*',$packed); substr($binary,$pre)='0'x($bits-$pre); $packed=pack('B*',$binary); my $n;
    if($f==4){$n=join('.',unpack('C4',$packed))}
    else{my @w=unpack('n8',$packed); my($best,$len)=(-1,0);for(my $i=0;$i<8;){if($w[$i]){$i++;next}my $j=$i;$j++ while $j<8&&!$w[$j];if($j-$i>$len&&$j-$i>=2){($best,$len)=($i,$j-$i)}$i=$j}my @h=map {sprintf '%x',$_} @w;if($best<0){$n=join(':',@h)}else{my $l=$best?join(':',@h[0..$best-1]):'';my $r=$best+$len<8?join(':',@h[$best+$len..7]):'';$n=$l.'::'.$r}}
    return ("$n/$pre","$f",$pre,$packed);
}
sub ips {my(%seen,@out);for(parts($_[0])){my($n)=ipnet($_);push @out,$n unless $seen{$n}++}fail('IP 不能为空') unless @out;\@out}
sub ports {my %p;for(parts($_[0])){fail("无效的端口：$_（有效范围 1-65535）") unless /\A[0-9]+\z/ && $_>=1 && $_<=65535;$p{0+$_}=1}fail('端口不能为空') unless %p;[sort {$a<=>$b} keys %p]}
sub protos {my $s=lc $_[0];$s=~tr{/}{,};$s='tcp,udp' if $s eq 'both';my %p=map {$_=>1} parts($s);fail('协议只能是 tcp、udp 或 both') unless %p&&!grep {$_ ne 'tcp'&&$_ ne 'udp'} keys %p;[grep {$p{$_}} qw(tcp udp)]}
sub families {my($s,$i)=@_;my %available=map {(ipnet($_))[1]=>1} @{$i||[]};my %f=$s eq 'auto'?%available:$s eq 'both'?('4'=>1,'6'=>1):($s=>1);fail('无效的地址族') unless %f&&!grep {$_ ne '4'&&$_ ne '6'} keys %f;fail('来源 IP 的地址族必须与所选地址族一致；选择 IPv4 + IPv6 时需同时提供 IPv4 和 IPv6 来源') if defined($i)&&join(',',sort keys %f) ne join(',',sort keys %available);[sort keys %f]}
sub empty {return {version=>3,targets=>{'4'=>[],'6'=>[]},rules=>{'4'=>{tcp=>{},udp=>{}},'6'=>{tcp=>{},udp=>{}}}}}
sub autotargets {
    my $a=$json->decode($ENV{IP_PORT_ALLOWLIST_AUTO_TARGETS}//'[]');fail('本机地址 JSON 无效') unless arr($a);
    my $t={'4'=>[],'6'=>[]};my %seen;
    for my $nic(@$a){fail('本机网卡 JSON 无效') unless obj($nic);next if ($nic->{ifname}//'') eq 'lo';my $info=$nic->{addr_info}//[];fail('本机地址列表无效') unless arr($info);
        for my $v(@$info){fail('本机地址条目无效') unless obj($v);next unless ($v->{scope}//'') eq 'global'&&(($v->{family}//'') eq 'inet'||($v->{family}//'') eq 'inet6');my $flags=$v->{flags}//[];fail('本机地址标志无效') unless arr($flags);next if $v->{tentative}||$v->{dadfailed}||grep {$_ eq 'tentative'||$_ eq 'dadfailed'} @$flags;my($n,$f,$p)=ipnet($v->{local});fail('本机地址的地址族不匹配') unless $f eq ($v->{family} eq 'inet'?'4':'6');fail('本机地址必须是单个主机地址') unless $p==($f eq '4'?32:128);push @{$t->{$f}},$n unless $seen{$n}++}
    }return $t;
}
sub targetguard {my($s)=@_;for my $f(qw(4 6)){fail("IPv$f 已有端口规则，但未配置目标主机地址；请先用菜单 8 或 targets --family $f --ips 主机地址 配置") if !@{$s->{targets}{$f}}&&(keys %{$s->{rules}{$f}{tcp}}||keys %{$s->{rules}{$f}{udp}})}}
sub targetlist {my($iv,$f)=@_;fail('目标主机地址族必须是 4 或 6') unless $f eq '4'||$f eq '6';my $i=ips($iv);for(@$i){my(undef,$fam,$p)=ipnet($_);fail('目标必须是对应地址族的单个主机地址（IPv4 /32，IPv6 /128）') unless $fam eq $f&&$p==($f eq '4'?32:128)}$i}
sub normalize {
    my($raw)=@_;fail('配置文件必须是 JSON 对象') unless obj($raw);my $s=empty();
    if(!exists $raw->{version}){$raw={version=>2,targets=>autotargets(),rules=>{'4'=>{tcp=>$raw,udp=>{}},'6'=>{tcp=>{},udp=>{}}}}}
    fail('不支持的配置文件格式') unless keysare($raw,qw(version targets rules))&&!ref($raw->{version})&&!str($raw->{version})&&($raw->{version}==2||$raw->{version}==3);
    for(qw(targets rules)){fail("配置字段无效：$_") unless keysare($raw->{$_},'4','6')}
    for my $f(qw(4 6)){my $t=$raw->{targets}{$f};fail('目标必须是字符串数组') unless arr($t)&&!grep {!str($_)} @$t;$s->{targets}{$f}=@$t?targetlist(join(',',@$t),$f):[];my $r=$raw->{rules}{$f};fail('配置中的协议表无效') unless keysare($r,qw(tcp udp));for my $pr(qw(tcp udp)){fail('配置中的端口表无效') unless obj($r->{$pr});for my $n(keys %{$r->{$pr}}){fail('配置中的端口无效') unless $n=~/\A[1-9][0-9]*\z/&&$n<=65535;my $i=$r->{$pr}{$n};fail('来源必须是字符串数组') unless arr($i)&&!grep {!str($_)} @$i;fail('空来源数组需要配置版本 3') if !@$i&&$raw->{version}!=3;my $src=@$i?ips(join(',',@$i)):[];fail('来源与地址族不匹配') if grep {(ipnet($_))[1] ne $f} @$src;$s->{rules}{$f}{$pr}{$n}=$src}}}targetguard($s);return $s;
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
        fail('请至少指定 --proto、--new-ips 或 --new-ports') unless defined($pro)||length($ni)||length($np);
        my $newi=length($ni)?ips($ni):undef;my $newp=length($np)?ports($np):undef;
        my %selected=map {$_=>1} @$i;my %ports=map {$_=>1} @$ports;my(@m,%mi,%mp,%mf);
        for my $f(qw(4 6)){for my $p(qw(tcp udp)){for my $n(keys %{$state->{rules}{$f}{$p}}){my @chosen=grep {$selected{$_}} @{$state->{rules}{$f}{$p}{$n}};next unless $ports{$n}&&@chosen;push @m,[$f,$p,$n,\@chosen];$mi{$_}=1 for @chosen;$mp{$n}=1;$mf{$f}=1}}}
        fail('没有匹配的来源与端口关联') unless @m;
        fail('所选来源中有的与这些端口没有关联') unless join(',',sort keys %mi) eq join(',',sort @$i);
        fail('所选端口中有的与这些来源没有关联') unless join(',',sort keys %mp) eq join(',',sort @$ports);
        if(defined $newi){my %nf=map {(ipnet($_))[1]=>1} @$newi;fail('新来源的地址族必须与所选规则的地址族一致') unless join(',',sort keys %nf) eq join(',',sort keys %mf)}
        for(@m){my($f,$p,$n,$chosen)=@$_;my %c=map {$_=>1} @$chosen;my @left=grep {!$c{$_}} @{$s->{rules}{$f}{$p}{$n}};if(@left){$s->{rules}{$f}{$p}{$n}=\@left}else{delete $s->{rules}{$f}{$p}{$n}}}
        for(@m){my($f,$p,$n,$chosen)=@$_;my @src=defined($newi)?grep {(ipnet($_))[1] eq $f} @$newi:@$chosen;for my $dp(@{$pro||[$p]}){for my $dn(@{$newp||[$n]}){my $r=$s->{rules}{$f}{$dp};fail("IPv$f $dn/$dp 当前为拒绝全部来源；请用设置/替换白名单明确改写") if exists($r->{$dn})&&!@{$r->{$dn}};$r->{$dn}||=[];my %seen=map {$_=>1} @{$r->{$dn}};for my $src(@src){push @{$r->{$dn}},$src unless $seen{$src}++}}}}
        return @{changes($state,$s)}?normalize($s):$state;
    }
    my $f=families($fv,$i);for my $fam(@$f){for my $p(@$pro){for my $n(@$ports){if($cmd eq 'remove'){delete $s->{rules}{$fam}{$p}{$n}}elsif($cmd eq 'block'){$s->{rules}{$fam}{$p}{$n}=[]}else{$s->{rules}{$fam}{$p}{$n}=[grep {(ipnet($_))[1] eq $fam} @$i]}}}}return $s;
}
sub guard {
    my($s)=@_;my @c=split /\s+/,$ENV{SSH_CONNECTION}||'';return unless @c==4;
    fail('SSH_CONNECTION 无效') if $c[0]=~m{/}||$c[2]=~m{/}||$c[3]!~/\A[0-9]+\z/||$c[3]<1||$c[3]>65535;
    my(undef,$cf,undef,$client)=ipnet($c[0]);my(undef,$sf,undef,$server)=ipnet($c[2]);return unless grep {(ipnet($_))[3] eq $server} @{$s->{targets}{$sf}};
    my $r=$s->{rules}{$sf}{tcp};my $n=''.(0+$c[3]);return unless exists $r->{$n};my $ok=0;
    for(@{$r->{$n}}){my(undef,$f,$pre,$bytes)=ipnet($_);next unless $cf eq $f;my $b=unpack('B*',$client);substr($b,$pre)='0'x(length($b)-$pre);$ok=1 if pack('B*',$b) eq $bytes}
    fail("此配置会阻断当前 SSH 连接来源 $c[0]（TCP $n）；请把它加入白名单") unless $ok;
}
sub rows {
    my($s)=@_;my %g;for my $f(qw(4 6)){for my $p(qw(tcp udp)){for my $n(keys %{$s->{rules}{$f}{$p}}){$g{$_}{$n}{$p}=1 for @{$s->{rules}{$f}{$p}{$n}}}}}
    my @src=sort {my(undef,$af,$ap,$ab)=ipnet($a);my(undef,$bf,$bp,$bb)=ipnet($b);$af<=>$bf||$ab cmp $bb||$ap<=>$bp} keys %g;
    my @out;for my $src(@src){my @p;for my $n(sort {$a<=>$b} keys %{$g{$src}}){push @p,$n.'('.join('/',map {uc} grep {$g{$src}{$n}{$_}} qw(tcp udp)).')'}push @out,[$src,join(', ',@p)]}return \@out;
}
sub printstate {
    my($s)=@_;print "\n  已保存的端口策略\n";my $rows=rows($s);my $any=0;
    for my $f(qw(4 6)){
        my $targets=$s->{targets}{$f};print "\n  IPv$f 目标：",@$targets?join(', ',@$targets):'未配置（该地址族不可设置端口限制）',"\n";
        my @familyrows=grep {(ipnet($_->[0]))[1] eq $f} @$rows;
        print "  IPv$f 白名单\n" if @familyrows;
        for(@familyrows){print "  [IPv$f] ",$_->[0],' → ',$_->[1],"\n"}$any=1 if @familyrows;
        my %p;for my $pr(qw(tcp udp)){for my $n(keys %{$s->{rules}{$f}{$pr}}){$p{$n}{$pr}=1 unless @{$s->{rules}{$f}{$pr}{$n}}}}
        if(%p){$any=1;print "  拒绝全部来源 · IPv$f → ",join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$p{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %p),"\n"}
        print "  IPv$f 暂无受管端口限制\n" unless @familyrows||%p||!@$targets;
    }
    print $any?"\n  白名单端口仅允许所列来源；其他端口保持原有策略。\n":"\n  暂无受管端口限制\n";
}
sub summary {
    my($s)=@_;print "\n  当前概况\n";
    for my $f(qw(4 6)){
        my $t=$s->{targets}{$f};
        if(!@$t){print "  IPv$f 目标：未配置\n";next}
        my %p;for my $pr(qw(tcp udp)){$p{$_}{$pr}=1 for keys %{$s->{rules}{$f}{$pr}}}
        print "  IPv$f 目标：",join(', ',@$t)," · 受管端口：",(%p?join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$p{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %p):'无'),"\n";
    }
    print "  选择 1 查看完整白名单明细。\n";
}
sub chain {defined($_[0])&&!ref($_[0])&&$_[0]=~/\AIPW_[0-9a-f]{10}\z/}
sub tokens {my($a)=@_;fail('规则参数无效') unless arr($a)&&!grep {!str($_)||/[\x00\r\n]/} @$a}
sub snapshot_valid {
    my($s)=@_;fail('恢复快照无效') unless keysare($s,qw(chains rules hooks))&&arr($s->{chains})&&arr($s->{rules})&&arr($s->{hooks});my %c;for(@{$s->{chains}}){fail('恢复快照中的链无效') unless chain($_)&&!$c{$_}++}
    for(@{$s->{rules}}){tokens($_);fail('恢复快照中的规则无效') unless @$_>=2&&$_->[0] eq '-A'&&$c{$_->[1]}}
    my $last=0;for(@{$s->{hooks}}){fail('恢复快照中的挂钩无效') unless keysare($_,qw(position args));my $n=$_->{position};fail('恢复快照中的位置无效') unless defined($n)&&!ref($n)&&$n=~/\A[1-9][0-9]*\z/&&$n>$last;$last=$n;tokens($_->{args});my @a=@{$_->{args}};my $refs=0;for(my $i=0;$i<@a-1;$i++){if($a[$i] eq '-j'||$a[$i] eq '-g'){fail('恢复快照中的目标无效') unless $c{$a[$i+1]};$refs++}}fail('恢复挂钩必须恰好有一个目标') unless $refs==1}return $s;
}
sub logging_settings_valid {
    my($s)=@_;
    fail('恢复日志中的日志设置无效') unless keysare($s,qw(version operations connections max_mib keep retention_days rate burst auto_rotate));
    my %range=(version=>[1,1],max_mib=>[1,100],keep=>[1,20],retention_days=>[0,365],rate=>[1,100],burst=>[1,100]);
    for my $k(keys %range){my $v=$s->{$k};fail('恢复日志中的日志设置无效') unless defined($v)&&!ref($v)&&!str($v)&&$v=~/\A[0-9]+\z/&&$v>=$range{$k}[0]&&$v<=$range{$k}[1]}
    for my $k(qw(operations connections auto_rotate)){my $v=$s->{$k};my $rx=$k eq 'connections'?qr/\A(?:off|deny|all)\z/:qr/\A(?:off|on)\z/;fail('恢复日志中的日志设置无效') unless str($v)&&$v=~$rx}
    return $s;
}
sub journal {
    my $j=readjson($_[0]);fail('恢复日志无效') unless (keysare($j,qw(snapshots state))||keysare($j,qw(snapshots state logging)))&&obj($j->{snapshots})&&!grep {$_ ne '4'&&$_ ne '6'} keys %{$j->{snapshots}};
    snapshot_valid($_) for values %{$j->{snapshots}};
    fail('恢复状态无效') if defined($j->{state})&&!str($j->{state});normalize($json->decode($j->{state})) if defined $j->{state};
    if(exists($j->{logging})&&defined($j->{logging})){fail('恢复日志中的日志设置无效') unless str($j->{logging});logging_settings_valid($json->decode($j->{logging}))}
    return $j;
}
sub flagval { my($a,$n)=@_; for(my $i=0;$i<@$a-1;$i++){return $a->[$i+1] if $a->[$i] eq $n} return undef }
sub repair_fail { fail('实际规则无法无损还原为状态，请保留备份并人工核对') }
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
        fail('防火墙输出格式无效') unless $table;
        if($l=~/^:(\S+) (\S+) \[([0-9]+):([0-9]+)\]\z/){my($n,$pol,$pk,$by)=($1,$2,$3,$4);push @chains,{name=>$n,policy=>$pol,packets=>0+$pk,bytes=>0+$by} if $n=~/\AIPW_[0-9a-f]{10}\z/;next}
        fail('防火墙输出格式无效') unless $l=~/^(?:\[([0-9]+):([0-9]+)\] )?-A (\S+)(?:\s(.*))?\z/;
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
            my $prefix=substr($current,0,$end);my $boundary=rindex($prefix,'、');my $space=rindex($prefix,' ');$boundary=$space if $space>$boundary;
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
    fail('面板参数无效') unless defined($width)&&$width=~/\A[0-9]+\z/&&$width>=36&&$width<=108;
    ($ui_width,$ui_color,$ui_uni)=(0+$width,$color?1:0,$uni?1:0);$note//='';$status//='';
    print "\n";ui_edge($ui_uni?'╭':'+',$ui_uni?'╮':'+');
    if($kind eq 'title'){
        ui_lines($value,'1;36');ui_lines($note,'2') if length $note;
        ui_edge($ui_uni?'╰':'+',$ui_uni?'╯':'+');print "\n";return;
    }
    fail('面板类型无效') unless $kind eq 'menu';
    ui_lines('IP / 端口白名单管理','1;36');ui_lines('IPv4 / IPv6  ·  TCP / UDP','2');
    ui_lines($note,'33') if length $note;
    ui_section('当前规则 · 已保存');
    if(length $status){ui_lines('规则读取失败：'.$status,'31')}
    else{
        my $state=load($value);
        for my $f(qw(4 6)){ui_lines("IPv$f  ".(@{$state->{targets}{$f}}?join(', ',@{$state->{targets}{$f}}):'未配置'),'2')}
        my @entries=map {['允许  '.$_->[0].' → ',$_->[1],'32']} @{rows($state)};
        for my $f(qw(4 6)){
            my %ports;for my $pr(qw(tcp udp)){for my $n(keys %{$state->{rules}{$f}{$pr}}){$ports{$n}{$pr}=1 unless @{$state->{rules}{$f}{$pr}{$n}}}}
            my $ports=join(', ',map {my $n=$_;$n.'('.join('/',map {uc} grep {$ports{$n}{$_}} qw(tcp udp)).')'} sort {$a<=>$b} keys %ports);
            push @entries,["封锁  IPv$f / 全部来源 → ",$ports,'1;31'] if length $ports;
        }
        ui_lines('暂无白名单或封锁规则','33') unless @entries;
        for my $entry(@entries){
            my $prefix=ui_text($entry->[0]);my $indent=ui_width($prefix);my $limit=$ui_width-24;$limit=2 if $limit<2;$indent=$limit if $indent>$limit;
            ui_lines($prefix.$entry->[1],$entry->[2],' ' x $indent);
        }
    }
    ui_section('操作菜单');
    my @options=([1,'查看白名单 / 封锁规则','1;32'],[2,'设置 / 替换白名单','32'],[3,'编辑已有白名单','36'],[4,'取消指定端口限制','33'],[5,'清空全部限制','31'],[6,'查看实际防火墙规则','36'],[7,'封锁端口（拒绝全部来源）','1;31'],[8,'设置目标主机地址','36'],[9,'检查 / 安装依赖','36'],[10,'日志','36'],[11,'日志轮转与清除设置','36']);
    push @options,['R','修复损坏的状态文件','1;31'] if $broken;
    push @options,[0,'退出','2'];
    my @labels=map {($_->[0] eq '10' || $_->[0] eq '11' ? $_->[0].' '.$_->[1] : $_->[0].'  '.$_->[1])} @options;my $column=int(($ui_width-10)/2);my $longest=0;
    for(@labels){my $n=ui_width($_);$longest=$n if $n>$longest}
    if($column>=$longest){
        for(my $i=0;$i<@options;$i+=2){
            my $left=ui_style($labels[$i],$options[$i][2]);
            if($i+1<@options){$left.=' ' x ($column-ui_width($labels[$i])+4);$left.=ui_style($labels[$i+1],$options[$i+1][2])}
            ui_line($left,'');
        }
    }else{for(my $i=0;$i<@options;$i++){ui_lines($labels[$i],$options[$i][2])}}
    ui_section('输入编号 · Ctrl+C 退出');ui_edge($ui_uni?'╰':'+',$ui_uni?'╯':'+');print "\n";
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
    elsif($cmd eq 'check-sources'){my $s=load($ARGV[0]);my %f;for(@{ips($ARGV[1])}){$f{(ipnet($_))[1]}=1}for my $f(sort keys %f){fail("IPv$f 来源需要先配置 IPv$f 目标主机地址；请先用菜单 8 配置") unless @{$s->{targets}{$f}}}}
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
        for my $f(qw(4 6)){next if same($old->{targets}{$f},$new->{targets}{$f});$t=1;print "  IPv$f 目标：",join(', ',@{$old->{targets}{$f}}),' → ',join(', ',@{$new->{targets}{$f}}),"\n"}
        exit 3 unless @$c||$t;
        for(@$c){my($f,$pr,$n,$before,$after)=@$_;print "  IPv$f · $n/".uc($pr)."\n    原来：",!defined($before)?'未设置限制':@$before?join(', ',@$before):'拒绝全部来源',"\n    修改：",!defined($after)?'取消限制':@$after?join(', ',@$after):'拒绝全部来源',"\n"}
        print "  提醒：取消限制的旧协议/端口可能对公网开放。\n" if grep {!defined $_->[4]} @$c;
    }
    elsif($cmd eq 'selection'){my($v,$count)=@ARGV;my %sel;if(lc($v)=~/\A(?:all|a|全部|\*)\z/){$sel{$_}=1 for 0..$count-1}else{for(parts($v)){fail('请输入序号，例如 1,3 或 1-3，或输入 all 全选') unless /\A([0-9]+)(?:-([0-9]+))?\z/;my($l,$r)=(0+$1,defined($2)?0+$2:0+$1);fail("序号超出范围 1-$count") unless 1<=$l&&$l<=$r&&$r<=$count;$sel{$_}=1 for $l-1..$r-1}}fail('请至少选择一项') unless %sel;print "$_\n" for sort {$a<=>$b} keys %sel}
    elsif($cmd eq 'protos'){print join(',',@{protos($ARGV[0])}),"\n"}
    elsif($cmd eq 'state-lines'){my($p,$f)=@ARGV;my $s=load($p);for my $pr(qw(tcp udp)){for my $n(sort {$a<=>$b} keys %{$s->{rules}{$f}{$pr}}){print "allow\t$pr\t$n\t$_\n" for @{$s->{rules}{$f}{$pr}{$n}};print "deny\t$pr\t$n\n"}}for my $t(reverse @{$s->{targets}{$f}}){for my $pr(reverse qw(tcp udp)){print "hook\t$pr\t$t\n" if keys %{$s->{rules}{$f}{$pr}}}}}
    elsif($cmd eq 'snapshot-pack'){my $p=$ARGV[0];open my $h,'<:encoding(UTF-8)',$p or fail("无法读取 $p：$!");my $s={chains=>[],rules=>[],hooks=>[]};while(<$h>){my $a=$json->decode($_);my $t=shift @$a;if($t eq 'chain'){push @{$s->{chains}},$a->[0]}elsif($t eq 'rule'){push @{$s->{rules}},$a}elsif($t eq 'hook'){my $n=shift @$a;push @{$s->{hooks}},{position=>0+$n,args=>$a}}else{fail('快照记录无效')}}close $h;emit(snapshot_valid($s))}
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
            fail("IPv$f 已有端口规则，但目标主机地址为空；一致性校验失败，请保留至少一个 IPv$f 目标主机地址") if !@$b&&%ports;
            if(%ports){print "  IPv$f 目标：",@$a?join(', ',@$a):'未配置',' → ',@$b?join(', ',@$b):'未配置',"\n";print "    影响：",scalar(keys %ports)," 个端口（$combos 个端口/协议组合）、",scalar(keys %sources)," 条来源、共 $rules 条白名单将改为作用于新目标；\n         原目标地址不再受这些规则约束。\n"}
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
                fail("IPv$f 受管链挂钩缺少目标地址或协议，无法重建状态") unless defined($proto)&&defined($dest);
                fail("IPv$f 受管链挂钩的协议无效：$proto") unless $proto eq 'tcp'||$proto eq 'udp';
                my($n,$nf,$pre)=ipnet($dest);
                fail("IPv$f 受管链挂钩的目标必须是本地址族的单个主机地址：$dest") unless $nf eq $f&&$pre==($f eq '4'?32:128);
                $targets{$proto}{$n}=1;
            }
            for my $r(@{$snap->{rules}}){
                my(undef,$chain,@a)=@$r;
                next if rebuild_log(\@a);
                my $fields=rebuild_fields(\@a,'rule');
                my($proto,$port,$src,$jump)=@{$fields}{qw(proto port src jump)};
                fail("IPv$f 受管链 $chain 的规则缺少协议或端口，无法重建状态") unless defined($proto)&&defined($port);
                fail("IPv$f 受管链 $chain 的协议无效：$proto") unless $proto eq 'tcp'||$proto eq 'udp';
                fail("IPv$f 受管链 $chain 的端口无效：$port") unless $port=~/\A[1-9][0-9]*\z/&&$port<=65535;
                fail("IPv$f 受管链 $chain 的动作无效：".($jump//'缺少'),"；请勿在受管链中手工添加规则") unless defined($jump)&&($jump eq 'RETURN'||$jump eq 'DROP');
                if($jump eq 'DROP'){
                    fail("IPv$f 受管链 $chain 的 DROP 规则带有来源地址，无法重建状态") if defined $src;
                    repair_fail() if $agg{$proto}{0+$port}{drop};
                    $agg{$proto}{0+$port}{drop}=1;next;
                }
                fail("IPv$f 受管链 $chain 的放行规则缺少来源地址") unless defined($src);
                repair_fail() if $agg{$proto}{0+$port}{drop};
                my($sn,$sf)=ipnet($src); fail("IPv$f 受管链 $chain 的来源地址族不匹配：$src") unless $sf eq $f;
                push @{$agg{$proto}{0+$port}{sources}},$sn unless grep {$_ eq $sn} @{$agg{$proto}{0+$port}{sources}||[]};
            }
            for my $pr(qw(tcp udp)){for my $n(keys %{$agg{$pr}||{}}){
                fail("IPv$f 端口 $n/$pr 缺少拒绝兜底规则（DROP），实际规则与状态模型不一致，拒绝重建") unless $agg{$pr}{$n}{drop};
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
        fail('当前内核没有受管规则，无法从实际规则重建状态；请改用重建为空状态') unless $found;
        emit(normalize($s));
    }
    else{fail("未知的数据操作：$cmd")}
    1;
};if(!$ok){my $e=$@||'数据处理失败';$e=~s/ at .* line \d+.*//s;print STDERR "错误：$e";print STDERR "\n" unless $e=~/\n\z/;exit 2}
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
    err_prefix                => '日志引擎错误：',
    warn_prefix               => '日志引擎警告：',
    err_usage                 => '用法：logging-engine.pl LOGDIR 命令 [参数]',
    err_unknown_command       => '未知命令 %s',
    err_missing_args          => '命令 %s 缺少参数',
    err_extra_args            => '命令 %s 不接受多余参数 %s',
    err_internal              => '内部错误：%s',
    err_sync                  => '同步 %s 失败（退出状态 %s）',
    err_logdir_absolute       => 'LOGDIR 必须是绝对路径：%s',
    err_logdir_name           => '日志目录名必须是 %s，实际是 %s',
    err_parent_missing        => '日志目录的父目录不存在：%s',
    err_parent_not_dir        => '日志目录的父目录不是真实目录（缺失、符号链接或特殊文件）：%s',
    err_parent_owner          => '日志目录的父目录不是 root 所有（uid %s）：%s',
    err_parent_mode           => '日志目录的父目录允许组或其他用户写入（权限 %s）：%s',
    err_logdir_special        => '日志目录不是真实目录（符号链接或特殊文件）：%s',
    err_logdir_owner          => '日志目录不是 root 所有（uid %s）：%s',
    err_logdir_mode           => '日志目录权限是 %s，必须是 0700：%s',
    err_logdir_stat           => '无法读取日志目录状态 %s：%s',
    err_logdir_create         => '无法创建日志目录 %s：%s',
    label_file_lock           => '锁文件',
    label_file_settings       => '设置文件',
    label_file_cursor         => '游标文件',
    label_file_log            => '日志文件',
    label_file_archive        => '归档文件',
    label_file_input          => '输入文件',
    err_file_special          => '%s 不是 root 所有的普通文件（符号链接、硬链接或特殊文件）：%s',
    err_file_owner            => '%s 不是 root 所有（uid %s）：%s',
    err_file_nlink            => '%s 的硬链接数是 %s，必须是 1：%s',
    err_file_mode             => '%s 权限是 %s，必须是 0600：%s',
    err_file_stat             => '无法读取 %s 的状态：%s',
    err_file_read             => '无法读取 %s：%s',
    err_file_write            => '无法写入 %s：%s',
    err_file_open             => '无法打开 %s：%s',
    err_file_rename           => '无法把 %s 重命名为 %s：%s',
    err_file_unlink           => '无法删除 %s：%s',
    err_file_chmod            => '无法把 %s 的权限设为 0600：%s',
    err_file_create           => '无法创建 %s：%s',
    err_dir_create            => '无法创建目录 %s：%s',
    err_lock_open             => '无法打开锁文件 %s：%s',
    err_lock_flock            => '无法锁定 %s：%s',
    err_skip_unsafe           => '已跳过不安全的文件，未删除：%s',
    err_settings_json         => '设置文件不是合法 JSON：%s：%s',
    err_settings_not_object   => '设置内容必须是 JSON 对象',
    err_settings_version      => '设置版本 %s 无效，只支持整数 1',
    err_settings_missing_key  => '设置缺少项 %s',
    err_settings_unknown_key  => '设置包含未知项 %s',
    err_settings_type         => '设置项 %s 必须是整数',
    err_settings_enum         => '设置项 %s 的值 %s 无效，可用值：%s',
    err_settings_range        => '设置项 %s 的值 %s 无效，有效范围：%s 到 %s',
    err_settings_input_json   => '输入文件不是合法 JSON：%s：%s',
    err_cursor_json           => '游标文件不是合法 JSON：%s：%s',
    err_cursor_not_object     => '游标内容必须是 JSON 对象',
    err_cursor_unknown_key    => '游标包含未知项 %s',
    err_cursor_field          => '游标字段 %s 缺失或类型不正确',
    err_import_lines          => '输入文件行数 %s 超过上限 %s',
    err_import_bytes          => '输入文件超过 %s 字节上限',
    err_import_json           => '输入第 %s 行不是合法 JSON：%s',
    err_import_object         => '输入第 %s 行不是 JSON 对象',
    err_import_field          => '输入第 %s 行字段 %s 缺失或类型不正确',
    err_record_long           => '记录长度超过 %s 字节上限',
    err_log_line_long         => '日志行超过 %s 字节上限：%s',
    err_view_json             => '日志文件 %s 不是合法 JSON：%s',
    err_view_schema           => '日志文件 %s 的记录结构不正确',
    err_bad_type              => '日志类型 %s 无效，可用值：operations、connections、both',
    err_bad_format            => '输出格式 %s 无效，可用值：json、text',
    err_bad_limit             => '条数 %s 无效，必须是 1 到 1000 之间的整数',
    err_bad_exit_code         => '退出码 %s 无效，必须是 0 到 255 之间的整数',
    err_bad_action            => 'action %s 无效，只允许小写字母、数字、下划线和连字符，长度 1 到 64',
    err_bad_confirm           => '确认串不正确，必须精确输入 CLEAR',
    err_bad_setting_key       => '设置项 %s 无效，可用项：operations、connections、max_mib、keep、retention_days、rate、burst、auto_rotate',
    label_settings_header     => '日志引擎设置',
    label_settings_line       => '%s：%s',
    label_version             => '配置版本',
    label_operations          => '操作日志',
    label_connections         => '连接日志',
    label_both                => '操作与连接日志',
    label_max_mib             => '单文件大小上限（MiB）',
    label_keep                => '保留份数',
    label_retention_days      => '保留天数',
    label_rate                => '连接日志限速（每分钟）',
    label_burst               => '连接日志突发',
    label_auto_rotate         => '自动轮转',
    decision_allow            => '放行',
    decision_deny             => '拒绝',
    fmt_text_operation        => '%s 操作 %s 退出码=%s %s',
    fmt_text_connection       => '%s 连接 %s %s:%s 到 %s:%s 协议=%s 入=%s 出=%s %s',
    msg_rotate_done           => '已轮转 %s',
    msg_rotate_empty          => '%s 的活跃日志为空，未轮转',
    msg_rotate_missing        => '%s 的活跃日志不存在，未轮转',
    msg_clear_done            => '已清除 %s 的日志文件',
    msg_clear_mark            => '清除水位线已更新为 %s 微秒',
    msg_settings_removed      => '设置文件已删除',
    msg_import_done           => '已导入连接记录 %s 条，跳过重复 %s 条，跳过清除水位线之前的记录 %s 条',
    msg_stats_logdir          => '日志目录：%s',
    msg_stats_stream          => '%s：活跃文件 %s，%s 字节，%s 条记录，归档 %s 份',
    msg_stats_archive         => '归档 %s：%s 字节',
    msg_stats_cursor          => '游标文件：%s',
    msg_stats_cursor_yes      => '存在',
    msg_stats_cursor_no       => '不存在',
    msg_stats_settings        => '当前设置：',
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
    ((EUID==0)) || { error '需要 root 权限'; return 2; }
    [[ -d $DIR && ! -L $DIR ]] || { error "状态目录不存在或不是普通目录：$DIR"; return 2; }
    local tool
    for tool in perl sync mktemp rm cat timeout flock; do
        have_tool "$tool" || { error "日志功能缺少工具：$tool"; return 2; }
    done
    perl -MJSON::PP -MFcntl -MFile::Temp -MCwd -MPOSIX -MTime::HiRes -MDigest::SHA -MFile::Basename -MFile::Spec -MErrno -MB -e 'exit 0' || { error '日志功能需要完整 Perl 核心模块'; return 2; }
}
logging_audit() {
    local action=$1 code=$2 detail=${3:-}
    ((EUID==0)) && have_tool perl || return 0
    if ! log_data audit "$action" "$code" "$detail" > /dev/null; then
        error '操作结果已确定，但操作日志写入失败；请检查日志目录、权限与磁盘空间'
    fi
    return 0
}
logging_runtime() {
    local input=${1:-$WORK/log-runtime.json} values
    if (($#==0)); then log_data settings-json > "$input" || return 2; fi
    values=$(perl -MJSON::PP -e 'local $/; open my $h,"<",$ARGV[0] or die "$!\n"; my $s=JSON::PP->new->decode(<$h>); print join("\t",@$s{qw(connections rate burst)}),"\n"' "$input") || return 2
    IFS=$'\t' read -r LOG_MODE LOG_RATE LOG_BURST <<< "$values"
    [[ $LOG_MODE == off || $LOG_MODE == deny || $LOG_MODE == all ]] && [[ $LOG_RATE =~ ^[1-9][0-9]*$ && $LOG_BURST =~ ^[1-9][0-9]*$ ]] && ((LOG_RATE<=100 && LOG_BURST<=100)) || { error '日志运行设置无效'; return 2; }
    LOG_PREFIX=$(log_data prefix) || return 2
    [[ $LOG_PREFIX =~ ^IPW_[0-9a-f]{10}$ ]] || { error '日志实例标识无效'; return 2; }
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
    printf '日志设置已保存。\n'
}
logging_collect() {
    local prefix fields cursor boot clear current rc since help
    local -a args=()
    LOG_SOURCE_STATUS=unavailable
    if ! have_tool journalctl; then error '连接日志来源不可用：未找到 journalctl；仍可查看已保存记录'; return 0; fi
    help=$(LC_ALL=C journalctl --help 2>&1) || { error '连接日志来源不可用：无法检测 journalctl；仍可查看已保存记录'; return 0; }
    if [[ $help != *--grep* || $help != *--after-cursor* ]]; then error '连接日志来源不可用：journalctl 不支持过滤或游标；仍可查看已保存记录'; return 0; fi
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
        error '连接日志来源暂不可读；仍可查看已保存记录'
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
        (($#==3)) || { error 'log-settings --set 需要设置项和值'; return 2; }
        cli _logging-config "$2" "$3"; return $?
    fi
    while (($#)); do
        option=$1; shift
        case $option in
            --json) [[ $cmd == logs || $cmd == log-settings ]] || { error '此日志命令不接受 --json'; return 2; }; format=json ;;
            --status) [[ $cmd == logs ]] || { error '此日志命令不接受 --status'; return 2; }; status=1 ;;
            --type) [[ $cmd == logs || $cmd == log-rotate || $cmd == log-clear ]] && (($#)) || { error '此日志命令不接受 --type 或缺少值'; return 2; }; type=$1; shift ;;
            --lines) [[ $cmd == logs ]] && (($#)) || { error '此日志命令不接受 --lines 或缺少值'; return 2; }; lines=$1; shift ;;
            --confirm) [[ $cmd == log-clear ]] && (($#)) || { error '此日志命令不接受 --confirm 或缺少值'; return 2; }; confirm=$1; shift ;;
            -h|--help) usage; return 0 ;;
            *) error "未知日志选项：$option"; return 2 ;;
        esac
    done
    [[ $type == operations || $type == connections || $type == both ]] || { error '日志类型必须是 operations、connections 或 both'; return 2; }
    [[ $lines =~ ^[0-9]{1,4}$ ]] && ((10#$lines>=1 && 10#$lines<=1000)) || { error '日志条数必须是 1 到 1000 的整数'; return 2; }
    [[ $cmd != log-clear || $confirm == CLEAR ]] || { error '清除日志必须用 --confirm CLEAR 确认'; return 2; }
    WORK='' TRANSACTION=0 RECOVERY_KEEP=0 LOG_SAVE_PENDING=0 AUDIT_ACTION=''
    trap cleanup EXIT
    trap 'printf "\n操作已中断\n" >&2; exit 130' INT TERM
    logging_require || return 2
    WORK=$(mktemp -d "$DIR/.ip-port-allowlist-work.XXXXXXXX") || { error '无法创建日志临时目录'; return 2; }
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
                    printf '连接日志来源：%s（查看时采集，限速数据包采样）\n' "${LOG_SOURCE_STATUS:-unavailable}"
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
            ((verbose==0)) || printf '缺少工具或所需能力：%s（依赖 %s）\n' "$tool" "$package" >&2
        fi
    done
    if have_tool perl; then
        if ! details=$(perl_probe 2>&1); then
            missing[perl]=1; bad=1
            if ((verbose)); then printf 'Perl 核心模块或 UTF-8 编码支持不完整；需要完整 perl，perl-base 不足。\n%s\n' "$details" >&2; fi
        fi
    fi
    if [[ $scope == full ]]; then
        for tool in /usr/sbin/iptables /usr/sbin/ip6tables /usr/sbin/iptables-restore /usr/sbin/ip6tables-restore /usr/sbin/iptables-save /usr/sbin/ip6tables-save; do
            if ! have_firewall "$tool"; then
                missing[iptables]=1; bad=1
                ((verbose==0)) || printf '缺少防火墙工具：%s（软件包 iptables）\n' "$tool" >&2
            fi
        done
    fi
    for package in perl iptables util-linux coreutils awk grep iproute2; do [[ ! ${missing[$package]+x} ]] || MISSING_PACKAGES+=("$package"); done
    ((bad==0))
}
require_tools() {
    if ! dependency_scan 0 "${1:-full}"; then
        dependency_scan 1 "${1:-full}" || :
        error '依赖不完整，操作已停止。请选择菜单 9，或运行 doctor / doctor --install。'
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
    if (($#)); then [[ $# == 1 && $1 == --install ]] || { error '用法：doctor [--install]'; return 2; }; install=1; fi
    if dependency_scan 1 full; then printf '依赖检查通过；无需安装。\n'; return 0; fi
    if ((install==0)); then error '依赖检查失败。请选择菜单 9，或运行 doctor --install。'; return 2; fi
    if ! manager=$(package_manager); then
        error '未找到支持的包管理器（apt-get/dnf/yum/apk）；请手动安装缺少的依赖：'
        printf '  %s\n' "${MISSING_PACKAGES[@]}" >&2
        return 2
    fi
    ((EUID==0)) || { error '安装依赖需要 root 权限；请以 root 或 sudo 运行 doctor --install'; return 2; }
    map_packages "$manager" "${MISSING_PACKAGES[@]}"
    printf '包管理器：%s\n将安装缺少的软件包：%s\n' "$manager" "${INSTALL_PACKAGES[*]}"
    printf '仅安装依赖；不会修改防火墙规则、配置或定时任务。输入 yes 确认安装：'
    if ! IFS= read -r answer || [[ $answer != yes ]]; then printf '\n已取消，未执行安装。\n'; return 0; fi
    rc=0
    install_packages "$manager" "${INSTALL_PACKAGES[@]}" || rc=2
    if dependency_scan 1 full; then
        if ((rc)); then error '安装命令失败，虽然当前依赖检查通过，请检查包管理器错误'; return 2; fi
        printf '安装完成，依赖检查通过。\n'
        return 0
    fi
    error '安装失败或依赖仍不完整；请检查包管理器错误和 PATH 后重试。'
    return 2
}
run() { timeout --foreground --kill-after=5 30 "$@" || { error "命令执行失败或超时：$1"; return 2; }; }
firewall() {
    local tool=iptables
    [[ $1 == 4 ]] || tool=ip6tables
    command -v "$tool${2:-}" || { error "找不到防火墙命令：$tool${2:-}"; return 2; }
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
        rm -f -- "$temporary"; error "原子保存失败：$target"; return 2
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
        lex_rule "$line" || { error '无法解析防火墙规则'; return 2; }
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
                [[ ${TOKENS[1]} == PREROUTING ]] || { error "受管链 $target 被其他链引用，拒绝修改"; return 2; }
                found=0; for chain in "${chains[@]}"; do [[ $target == "$chain" ]] && found=1; done
                ((found)) || { error "受管链 $target 的定义缺失"; return 2; }
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
    if ((failures)); then error '规则回滚未完成，已保留恢复记录'; return 2; fi
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
        error "恢复记录删除未持久化；备份保留在 $saved"
        return 2
    fi
    printf '已回滚上次未完成的更新\n' >&2
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
                error "更新失败且回滚未完成；恢复材料保留在 $WORK，请运行 recover"
                ((rc==130)) || rc=2
            fi
        else
            RECOVERY_KEEP=1; error "恢复记录缺失；临时材料保留在 $WORK"; ((rc==130)) || rc=2
        fi
    fi
    if ((LOG_SAVE_PENDING)); then
        if ! logging_restore_settings "$LOG_BEFORE"; then
            RECOVERY_KEEP=1; error "日志设置回滚失败；旧设置保留在 $WORK"; rc=2
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
    if ((dry)); then for f in "${plans[@]}"; do printf '# IPv%s（预检通过，未提交）\n' "$f"; cat -- "$WORK/plan.$f"; done; return 0; fi
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
        printf '\nIPv%s 实际受管规则：\n' "$f"
        awk '/^-N IPW_[0-9a-f]+$/ {print; next} /^-A / && /(^|[[:space:]])IPW_[0-9a-f]+([[:space:]]|$)/ {print}' "$WORK/raw.$f"
        if grep -q '^-N IPW_' "$WORK/raw.$f"; then
            tool=$(firewall "$f" -save) || return 2
            run "$tool" -c -t raw > "$WORK/counters.$f" || return 2
            printf '计数器：\n'
            while IFS= read -r line; do
                if [[ $line =~ ^-N\ (IPW_[0-9a-f]{10})$ ]]; then
                    chain=${BASH_REMATCH[1]}; awk -v c="$chain" 'index($0,c) {print}' "$WORK/counters.$f"
                fi
            done < "$WORK/raw.$f"
        else printf '无受管链\n'; fi
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
用法：ip-port-allowlist.sh [命令] [选项]；无参数启动菜单。
  validate/set --ips IP[,CIDR] --ports PORT[,PORT] [--proto tcp|udp|both]
               [--family auto|4|6|both]
  edit --ips SOURCES --ports PORTS [--proto PROTOCOLS]
       [--new-ips SOURCES] [--new-ports PORTS]
  remove --ports PORTS [--family 4|6|both] [--proto PROTOCOLS]
  block --ports PORTS [--family 4|6|both] [--proto PROTOCOLS]
  targets --family 4|6 --ips HOST[,HOST] (仅 /32 或 /128)
  clear --all
  show [--json|--live|--live --json]
  restore
  recover
  repair-state [--from-live|--empty|--backup-only] [--dry-run]（状态文件损坏时的引导修复）
  doctor [--install]（只检测；--install 需明确输入 yes）
  logs [--type operations|connections|both] [--lines 1..1000] [--json|--status]
  log-settings [--json] | log-settings --set KEY VALUE
  log-rotate [--type operations|connections|both]
  log-clear [--type operations|connections|both] --confirm CLEAR
  log-maintain
连接日志默认关闭；开启后记录本脚本规则匹配的限速数据包采样，查看时采集。
日志只写入本状态目录的 .ip-port-allowlist.logs；清除不会删除系统 journal。
set/remove/block 默认协议 TCP/UDP；set 默认地址族 auto；remove/block 默认 IPv4+IPv6。
修改命令和 restore 支持 --dry-run；修改命令支持 --expect-state SHA256。
IP_PORT_ALLOWLIST_DIR 默认 /root；路径可含空格。需要 Bash 4.4+ 和完整 Perl 核心模块。
缺失/旧版配置目标自动检测本机非 lo 的 scope global 地址（包含 NAT 私网和桥地址）。
无全局地址的地址族目标为空；为该地址族设置规则前请用 targets 配置目标。
菜单 9 / doctor --install 支持已有 apt-get、dnf、yum、apk；未知系统请手动安装。
--live --json 输出结构化实际规则（受管链、规则、挂钩与计数器），便于外部监控消费。
repair-state 仅在状态文件无法解析时使用；默认只备份（--backup-only），重建状态需输入 yes。
HELP
}
cli() {
    case ${1:-} in logs|log-settings|log-rotate|log-clear|log-maintain) logging_cli "$@"; return $? ;; esac
    if [[ ${1:-} == doctor ]]; then
        trap - EXIT
        trap 'printf "\n操作已中断\n" >&2; exit 130' INT TERM
        shift; doctor "$@"; local doctor_rc=$?; logging_audit doctor "$doctor_rc" ''; return "$doctor_rc"
    fi
    WORK='' TRANSACTION=0 RECOVERY_KEEP=0 AUTO_ADDRESSES='' LOG_CANDIDATE='' LOG_BEFORE='' LOG_SAVE_PENDING=0 AUDIT_ACTION='' AUDIT_DETAIL=''
    trap cleanup EXIT
    trap 'printf "\n操作已中断\n" >&2; exit 130' INT TERM
    local cmd=${1:-} ips='' ports='' proto='' family='' ni='' np='' expect='' repair='' dry=0 all=0 json=0 live=0 option val token
    local have_ips=0 have_ports=0 have_proto=0 have_family=0 have_ni=0 have_np=0 have_expect=0
    [[ $cmd == -h || $cmd == --help ]] && { usage; exit 0; }
    local log_key='' log_value=''
    case $cmd in validate|set|edit|remove|block|clear|show|restore|recover|targets|repair-state|_logging-config) ;; *) die "未知命令：$cmd" ;; esac
    shift
    if [[ $cmd == _logging-config ]]; then
        (($#==2)) || die '日志设置需要设置项和值'
        log_key=$1 log_value=$2; shift 2; AUDIT_ACTION=log-settings
    elif [[ $cmd != show && $cmd != validate ]]; then AUDIT_ACTION=$cmd; fi
    while (($#)); do
        option=$1; shift
        case $option in
            -h|--help) usage; exit 0 ;;
            --ips|--ports|--proto|--family|--new-ips|--new-ports|--expect-state)
                (($#)) || die "$option 缺少值"; val=$1; shift
                case $option in
                    --ips) ips=$val; have_ips=1 ;; --ports) ports=$val; have_ports=1 ;;
                    --proto) proto=$val; have_proto=1 ;; --family) family=$val; have_family=1 ;;
                    --new-ips) ni=$val; have_ni=1 ;; --new-ports) np=$val; have_np=1 ;;
                    --expect-state) expect=$val; have_expect=1 ;;
                esac ;;
            --dry-run) dry=1 ;; --all) all=1 ;; --json) json=1 ;; --live) live=1 ;;
            --from-live) repair=from-live ;; --empty) repair=empty ;; --backup-only) repair=backup-only ;;
            *) die "未知选项：$option" ;;
        esac
    done
    case $cmd in
        validate|set) ((have_ips && have_ports)) || die '必须指定 --ips 和 --ports'; [[ -n $ips && -n $ports ]] || die '白名单和端口不能为空'; ((have_proto)) || proto=tcp,udp; ((have_family)) || family=auto ;;
        remove|block) ((have_ports)) || die '必须指定 --ports'; [[ -n $ports ]] || die '端口不能为空'; ((have_ips==0)) || die '此命令不接受 --ips'; if [[ $cmd == block ]]; then ((have_proto)) || proto=tcp,udp; ((have_family)) || family=both; else ((have_proto)) || proto=tcp,udp; ((have_family)) || family=both; fi ;;
        targets) ((have_ips && have_family)) || die 'targets 必须指定 --ips 和 --family'; ((have_ports==0 && have_proto==0)) || die 'targets 不接受端口或协议'; [[ -n $ips && ( $family == 4 || $family == 6 ) ]] || die 'targets 地址族必须是 4 或 6，目标不能为空' ;;
        edit) ((have_ips && have_ports)) || die '必须指定 --ips 和 --ports'; [[ -n $ips && -n $ports ]] || die '来源和端口不能为空'; ((have_proto || have_ni || have_np)) || die '请至少指定 --proto、--new-ips 或 --new-ports'; ((have_family==0)) || die 'edit 不接受 --family' ;;
        clear) ((all)) || die 'clear 必须指定 --all' ;;
        repair-state) [[ -n $repair ]] || repair=backup-only ;;
    esac
    [[ $cmd == edit ]] || ((have_ni==0 && have_np==0)) || die '此命令不接受 --new-ips/--new-ports'
    [[ $cmd == clear ]] || ((all==0)) || die '此命令不接受 --all'
    [[ $cmd == show ]] || ((json==0 && live==0)) || die '此命令不接受 --json/--live'
    [[ $cmd == repair-state ]] || [[ -z $repair ]] || die '此命令不接受 --from-live/--empty/--backup-only'
    if [[ $cmd == repair-state ]]; then
        ((have_ips==0 && have_ports==0 && have_proto==0 && have_family==0 && have_ni==0 && have_np==0 && have_expect==0 && all==0 && json==0 && live==0)) || die 'repair-state 不接受来源/端口/协议/地址族/新值/期望状态/--all/--json/--live'
    fi
    if [[ $cmd == show || $cmd == recover || $cmd == restore || $cmd == clear ]]; then ((have_ips==0 && have_ports==0 && have_proto==0 && have_family==0)) || die '此命令不接受来源/端口/协议/地址族选项'; fi
    if [[ $cmd == show || $cmd == recover || $cmd == validate ]]; then ((dry==0 && have_expect==0)) || die '此命令不接受 --dry-run/--expect-state'; fi
    [[ $cmd != restore ]] || ((have_expect==0)) || die 'restore 不接受 --expect-state'
    ((have_proto==0)) || [[ -n $proto ]] || die '协议不能为空'
    ((have_ni==0)) || [[ -n $ni ]] || die '新来源不能为空'
    ((have_np==0)) || [[ -n $np ]] || die '新端口不能为空'
    case $cmd in
        set|validate) [[ $family == auto || $family == 4 || $family == 6 || $family == both ]] || die '无效地址族' ;;
        remove|block) [[ $family == 4 || $family == 6 || $family == both ]] || die '无效地址族' ;;
    esac
    if [[ $cmd == validate ]]; then require_tools core || exit 2; data validate "$ips" "$ports" "$proto" "$family" || exit 2; exit 0; fi
    if [[ $cmd == _logging-config || $cmd == repair-state && $repair == backup-only ]]; then require_tools core || exit 2; else require_tools full || exit 2; fi
    AUDIT_DETAIL="dry_run=$dry"
    ((EUID==0)) || die '需要 root 权限'
    [[ -d $DIR ]] || die "状态目录不存在：$DIR"
    local namespace globaldir=/run/ip-port-allowlist
    namespace=$(stat -Lc '%i' /proc/self/ns/net) || die '无法读取网络命名空间标识'
    [[ $namespace =~ ^[0-9]+$ && ! -L $globaldir ]] || die '无效的共享锁目录或网络命名空间'
    if ! mkdir -p -- "$globaldir" || ! chmod 700 "$globaldir"; then die '无法创建共享防火墙锁目录'; fi
    exec 8>> "$globaldir/net.$namespace.lock" || die '无法打开共享防火墙锁'
    chmod 600 "$globaldir/net.$namespace.lock" || die '无法设置共享锁权限'
    flock -x 8 || die '无法获得共享防火墙锁'
    exec 9>> "$LOCK" || die '无法打开锁文件'
    chmod 600 "$LOCK" || die '无法设置锁文件权限'
    flock -x 9 || die '无法获得配置锁'
    WORK=$(mktemp -d "$DIR/.ip-port-allowlist-work.XXXXXXXX") || die '无法创建临时目录'
    if [[ $cmd == show ]] || ((dry)); then [[ ! -e $JOURNAL ]] || die '存在未完成的规则更新，请先运行 recover；暂停查看/预检'
    else recover_pending || exit 2; fi
    [[ $cmd != recover ]] || { printf '恢复检查完成\n'; exit 0; }
    if [[ $cmd == _logging-config ]]; then logging_configure "$log_key" "$log_value" || exit 2; exit 0; fi
    if [[ $cmd == repair-state ]]; then
        repair_state "$repair" "$dry" || exit 2
        exit 0
    fi
    data load "$STATE" > "$WORK/before" || exit 2
    if ((have_expect)); then token=$(state_token "$WORK/before") || exit 2; [[ $token == "$expect" ]] || die '配置已被其他会话修改；本次没有提交，请重新选择和预览'; fi
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
        if ((val==3)); then printf '配置没有变化，无需保存。\n'; exit 0; elif ((val)); then exit 2; fi
    fi
    if [[ $cmd == targets ]]; then
        data target-impact "$WORK/before" "$WORK/after" > "$WORK/impact"; val=$?
        if ((val==3)); then printf '目标主机地址没有变化，无需保存。\n'; exit 0; elif ((val)); then exit 2; fi
        cat -- "$WORK/impact"
    fi
    data guard "$WORK/after" || exit 2
    install "$WORK/after" "$dry" || exit 2
    if ((dry==0)); then styled '规则已更新并保存' '1;32'; data show "$WORK/after" || exit 2; fi
}

# Menu commands are isolated; the menu PID forwards cancellation and waits for rollback.
menu_interrupt() {
    trap '' INT TERM
    if [[ -n ${MENU_CHILD:-} ]]; then kill -TERM "$MENU_CHILD" 2>/dev/null || :; wait "$MENU_CHILD" || :; fi
    printf '\n操作已中断\n' >&2
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
    local subtitle="主菜单 › $1"
    [[ -z ${2:-} ]] || subtitle+='    /    随时输入 0 或 q 返回主菜单'
    if ! panel_render title "$1" "$(panel_width)" "$COLOR" "$UNI" "$subtitle" '' 0 2>/dev/null; then
        menu_rule;styled "  | $1" '1;36'
        [[ -z ${2:-} ]] || styled '    随时输入 0 或 q 返回主菜单' '2;37'
        menu_rule;printf '\n'
    fi
}
render_main_menu() {
    clear_page
    local state=''
    [[ -z ${MENUWORK:-} ]] || state=$MENUWORK/before
    if panel_render menu "$state" "$(panel_width)" "$COLOR" "$UNI" "$NOTICE" "$STATUS" "$broken" 2>/dev/null; then return 0; fi
    page 'IP / 端口白名单管理'
    [[ -z $NOTICE ]] || styled "  $NOTICE" 33
    [[ -z $STATUS ]] || error "$STATUS"
    menu_section '操作菜单'
    menu_option 1 '查看白名单 / 封锁规则'; menu_option 2 '设置 / 替换白名单'
    menu_option 3 '编辑已有白名单'; menu_option 4 '取消指定端口限制'
    menu_option 5 '清空全部限制' 31; menu_option 6 '查看实际防火墙规则'
    menu_option 7 '封锁端口（拒绝全部来源）' 31
    menu_option 8 '设置目标主机地址'; menu_option 9 '检查 / 安装依赖'
    menu_option 10 '日志'; menu_option 11 '日志轮转与清除设置'
    ((broken==0)) || menu_option R '修复损坏的状态文件' 31
    menu_option 0 '退出' '2;37';printf '\n'
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
    printf '  状态文件：%s\n' "$STATE"
    if [[ ! -e $STATE ]]; then
        printf '  文件不存在；首次保存时会自动创建。\n'
    else
        size=$(wc -c < "$STATE") || return 2
        sum=$(sha256sum -- "$STATE") || return 2
        printf '  大小：%s 字节；SHA256：%s\n' "$size" "${sum%% *}"
    fi
    [[ ! -e $JOURNAL ]] || printf '  注意：存在未完成的规则更新；修复前会先执行 recover。\n'
    for f in 4 6; do
        if tool=$(firewall "$f" -save) && out=$(run "$tool" -t raw); then
            printf '  内核 IPv%s：受管链 %s 条、规则 %s 条、挂钩 %s 条\n' "$f" \
                "$(grep -c '^:IPW_[0-9a-f]\{10\} ' <<< "$out")" \
                "$(grep -c '^-A IPW_[0-9a-f]\{10\} ' <<< "$out")" \
                "$(grep -cE '(^|[[:space:]])(-j|-g) IPW_[0-9a-f]{10}([[:space:]]|$)' <<< "$out")"
        else
            printf '  内核 IPv%s：无法读取实际规则\n' "$f"
        fi
    done
}
state_backup() {
    local stamp target n=0
    [[ -e $STATE ]] || { error "状态文件不存在：$STATE"; return 2; }
    stamp=$(date -u +%Y%m%dT%H%M%SZ) || return 2
    target=$STATE.corrupt.$stamp
    while [[ -e $target ]]; do ((n+=1)); target=$STATE.corrupt.$stamp.$n; done
    if ! cp -- "$STATE" "$target" || ! chmod 600 "$target" || ! sync -f "$target" || ! sync -f "$DIR"; then
        rm -f -- "$target"; error "备份损坏状态文件失败：$target"; return 2
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
    if [[ ! -e $STATE ]]; then printf '状态文件不存在，无需修复。\n'; return 0; fi
    if data load "$STATE" > "$WORK/healthy" 2> "$WORK/load.err"; then printf '状态文件正常，无需修复。\n'; return 0; fi
    reason=$(tr -d '\n' < "$WORK/load.err")
    printf '无法读取状态文件：%s\n' "${reason:-未知错误}" >&2
    case $mode in backup-only|empty|from-live) ;; *) error "未知的修复模式：$mode"; return 2 ;; esac
    if [[ $mode != backup-only ]]; then repair_rebuild "$mode" "$WORK/repaired" || return 2; fi
    if ((dry)); then
        printf '# 预检：未修改状态文件；模式=%s\n' "$mode"
        [[ $mode == backup-only ]] || { data show "$WORK/repaired" || return 2; }
        return 0
    fi
    if [[ $mode != backup-only ]]; then
        printf '修复会先备份损坏文件，再写入新状态。输入 yes 确认：'
        if ! IFS= read -r answer || [[ $answer != yes ]]; then printf '\n已取消，状态文件未修改。\n'; return 0; fi
    fi
    backup=$(state_backup) || return 2
    printf '损坏文件已备份：%s\n' "$backup"
    [[ $mode != backup-only ]] || return 0
    atomic_save "$WORK/repaired" "$STATE" || return 2
    printf '状态文件已重建：%s\n' "$STATE"
    data show "$STATE" || return 2
    if [[ $mode == empty ]]; then
        for f in 4 6; do
            tool=$(firewall "$f" -save) || continue
            out=$(run "$tool" -t raw 2>/dev/null) || continue
            grep -q '^:IPW_[0-9a-f]\{10\} ' <<< "$out" || continue
            printf '提示：状态已重建为空，但内核 IPv%s 仍有受管规则；如需让两者一致，请运行 restore。\n' "$f"
        done
    fi
}
repair_menu() {
    state_diagnose || return 2
    printf '\n'
    menu_option 1 '从内核实际规则重建状态' '' '按当前防火墙规则还原；需输入 yes'
    menu_option 2 '重建为空状态' '' '自动检测目标地址，无规则；需输入 yes'
    menu_option 3 '仅备份损坏文件' '' '不改状态文件，稍后手工修复'
    printf '\n'; menu_rule
    menu_option 0 '返回主菜单' '2;37'
    printf '\n'
    while :; do
        entry '  请选择 [0-3]：' || return $?
        case $REPLY in
            1) menu_cli repair-state --from-live || return $?; NOTICE='状态文件处理完成。'; return 10 ;;
            2) menu_cli repair-state --empty || return $?; NOTICE='状态文件处理完成。'; return 10 ;;
            3) menu_cli repair-state --backup-only || return $?; NOTICE='已备份损坏的状态文件。'; return 10 ;;
            0) return 10 ;;
            *) error '请输入 0-3' ;;
        esac
    done
}
menu_state() {
    [[ ! -e $JOURNAL ]] || { error '存在未完成的规则更新，请先运行 recover'; return 2; }
    AUTO_ADDRESSES=''
    data load "$STATE" > "$MENUWORK/before"
}
# ask PROMPT CHECK ARGS...: reprompt until "data CHECK ARGS... VALUE" passes; empty is rejected. ask_optional allows empty.
ask() {
    local prompt=$1; shift
    while :; do
        entry "$prompt" || return $?
        [[ -n $REPLY ]] || { error '不能为空'; continue; }
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
    printf '  协议\n'
    menu_option 1 'TCP'; menu_option 2 'UDP'; menu_option 3 'TCP/UDP'
    while :; do
        if [[ -n $default ]]; then entry "  请选择协议 [默认 $dl]：" "$default" || return $?
        else entry '  请选择协议 [1-3；Enter 保持原协议]：' || return $?; fi
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
        ((a4 || a6)) || { error '尚未配置任何目标主机地址；请先使用菜单 8 设置目标主机地址'; return 2; }
        if ((a4 && a6)); then default=3; elif ((a4)); then default=1; else default=2; fi
    fi
    case $default in 1) dl='1 = IPv4' ;; 2) dl='2 = IPv6' ;; 3) dl='3 = IPv4 + IPv6' ;; esac
    printf '  地址族\n'
    menu_option 1 'IPv4'; menu_option 2 'IPv6'
    [[ $mode != available ]] || menu_option 3 'IPv4 + IPv6'
    while :; do
        if [[ -n $default ]]; then entry "  请选择地址族 [默认 $dl]：" "$default" || return $?
        else entry '  请选择地址族 [1-2]：' || return $?; fi
        case $REPLY in
            1) family=4 ;;
            2) family=6 ;;
            3) [[ $mode == available ]] && family=both || { error '请输入 1 或 2'; continue; } ;;
            *) error '请输入有效的序号'; continue ;;
        esac
        if [[ $mode == available ]]; then
            if [[ $family == 4 || $family == both ]] && ((a4==0)); then error 'IPv4 未配置目标主机地址，无法设置端口限制；请选择其他地址族，或先用菜单 8 配置'; continue; fi
            if [[ $family == 6 || $family == both ]] && ((a6==0)); then error 'IPv6 未配置目标主机地址，无法设置端口限制；请选择其他地址族，或先用菜单 8 配置'; continue; fi
        fi
        REPLY=$family; return 0
    done
}
choose_many() {
    local count=$1
    while :; do
        entry '  序号 [1,3 / 1-3 / all；0 返回]：' || return $?
        if data selection "$REPLY" "$count" > "$MENUWORK/selection"; then mapfile -t SELECTED < "$MENUWORK/selection"; return 0; fi
    done
}
confirm_change() {
    local token rc impact=0
    page '变更预览 · 确认保存' back
    data transform "$MENUWORK/before" "$@" > "$MENUWORK/after" || return 2
    data changes "$MENUWORK/before" "$MENUWORK/after"; rc=$?
    if ((rc==3)); then NOTICE='配置没有变化，无需保存。'; return 10; elif ((rc)); then return 2; fi
    # Target changes are always reported with their impact on existing allow rules (exit 3 = no target change).
    data target-impact "$MENUWORK/before" "$MENUWORK/after" || impact=$?
    ((impact==0 || impact==3)) || return 2
    data guard "$MENUWORK/after" || return 2
    entry '  输入 y 保存；其他输入取消：' || return $?
    if [[ ${REPLY,,} != y ]]; then NOTICE='已取消，规则未修改。'; return 10; fi
    token=$(state_token "$MENUWORK/before") || return 2
    menu_cli "${SUBMIT[@]}" --expect-state "$token"
}
set_menu() {
    local ips ports proto
    menu_state || return 2
    printf '  IPv4 / IPv6 来源可混填；只填写 IPv4 不会修改 IPv6。\n'
    printf '  同一端口已有的来源列表会被整体替换；只想追加请使用“编辑已有白名单”。\n\n'
    ask '  允许的 IP/IP 段（逗号或空格分隔）：' check-sources "$MENUWORK/before" || return $?; ips=$REPLY
    ask '  限制的端口（逗号或空格分隔）：' check-ports || return $?; ports=$REPLY
    read_protocol 3 || return $?; proto=$REPLY
    SUBMIT=(set --ips "$ips" --ports "$ports" --proto "$proto")
    confirm_change set "$ips" "$ports" "$proto" auto '' ''
}
ports_menu() {
    local cmd=$1 ports family proto
    menu_state || return 2
    data show "$MENUWORK/before" || return 2
    if [[ $cmd == block ]]; then
        printf '  拒绝所选地址族、协议和端口的全部来源；仅作用于已配置目标。\n'
        ask '  要封锁的端口：' check-ports || return $?; ports=$REPLY
    else
        ask '  要取消限制的端口：' check-ports || return $?; ports=$REPLY
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
    ((i)) || { NOTICE='暂无规则可编辑，请先使用“设置 / 替换白名单”。'; return 10; }
    choose_many "$i" || return $?
    for i in "${SELECTED[@]}"; do sources+=${sources:+,}${source_options[i]}; done
    data available "$MENUWORK/before" "$sources" > "$MENUWORK/ports" || return 2
    page '编辑白名单 · 选择端口' back; i=0
    while IFS=$'\t' read -r source label; do port_options+=("$source"); ((i+=1)); printf '  [%s]  %s(%s)\n' "$i" "$source" "$label"; done < "$MENUWORK/ports"
    choose_many "$i" || return $?
    for i in "${SELECTED[@]}"; do ports+=${ports:+,}${port_options[i]}; done
    sources=$(data filter-sources "$MENUWORK/before" "$sources" "$ports") || return 2
    page '编辑白名单 · 修改内容' back
    printf '  来源：%s\n  端口：%s\n\n' "$sources" "$ports"
    menu_option 1 '修改协议'; menu_option 2 '修改来源 IP / IP 段'; menu_option 3 '修改端口'; menu_option 4 '综合编辑'
    while :; do entry '  请选择 [1-4；0 返回]：' || return $?; action=$REPLY; [[ $action =~ ^[1-4]$ ]] && break; done
    printf '  Enter 保持原值；未选中的 IP 和端口保持原样。\n'
    if [[ $action == 1 || $action == 4 ]]; then read_protocol || return $?; proto=$REPLY; fi
    if [[ $action == 2 || $action == 4 ]]; then ask_optional '  新来源 IP/IP 段（可填多个）：' check-sources "$MENUWORK/before" || return $?; ni=$REPLY; fi
    if [[ $action == 3 || $action == 4 ]]; then ask_optional '  新端口（可填多个）：' check-ports || return $?; np=$REPLY; fi
    [[ -n $proto || -n $ni || -n $np ]] || { NOTICE='配置没有变化，无需保存。'; return 10; }
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
    styled '  警告：将清空全部 IPv4/IPv6 TCP/UDP 限制，端口可能对公网开放。' 31
    entry '  输入 CLEAR 确认清空：' || return $?
    if [[ $REPLY == CLEAR ]]; then token=$(state_token "$MENUWORK/before") || return 2; menu_cli clear --all --expect-state "$token"; else NOTICE='已取消，规则未修改。'; return 10; fi
}
targets_menu() {
    local family ips
    menu_state || return 2
    data show "$MENUWORK/before" || return 2
    printf '  自动检测的目标包含本机所有非 lo 全局地址（含 Docker 网桥，如 172.17.0.1）；\n'
    printf '  如只需保护特定地址，请在此手动指定；输入会整体替换所选地址族的目标。\n\n'
    choose_family target || return $?; family=$REPLY
    ask '  新目标主机地址（多个用逗号或空格分隔；仅 /32 或 /128）：' check-hosts "$family" || return $?; ips=$REPLY
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
    printf '\n  按 Enter 继续…'; IFS= read -r REPLY || return 11
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
        error "请输入 $min-$max 之间的整数"
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
        error "可选值：$hint"
    done
}
log_apply() {
    local key=$1 value=$2 note=${3-}
    printf '  将把 %s 设为 %s\n' "$key" "$value"
    [[ -z $note ]] || styled "  $note" 33
    log_confirm '  输入 y 保存；其他输入取消：' || return $?
    if logging_set "$key" "$value"; then LOG_NOTICE='日志设置已保存。'; return 0; fi
    LOG_NOTICE='日志设置保存失败，请查看上方错误信息。'
    return 2
}
log_rotate() {
    printf '  将立即轮转 %s，仅作用于本脚本日志，不影响内核 journal。\n' "$1"
    log_confirm '  输入 y 执行轮转；其他输入取消：' || return $?
    if logging_rotate "$1"; then LOG_NOTICE='已完成轮转。'; return 0; fi
    LOG_NOTICE='轮转失败，请查看上方错误信息。'
    return 2
}
log_clear() {
    styled "  警告：将清除本脚本的 $1 日志，不会删除内核 journal 全局日志。" 31
    entry '  输入 CLEAR 确认清除；其他输入取消：' || return $?
    if [[ $REPLY != CLEAR ]]; then LOG_NOTICE='未输入 CLEAR，未清除日志。'; return 10; fi
    if logging_clear "$1" CLEAR; then LOG_NOTICE='已清除本脚本日志。'; return 0; fi
    LOG_NOTICE='清除失败，请查看上方错误信息。'
    return 2
}
log_show() {
    page "$3" back
    logging_view "$1" "$2" || error '日志读取失败，请查看上方后端错误信息'
    log_pause
}
logs_menu() {
    local lines=50 rc=0
    while :; do
        page '日志' back
        menu_section '当前状态'
        logging_status || error '无法读取日志状态，请查看上方后端错误信息'
        styled '  说明：连接日志为本脚本规则匹配的数据包限速采样，不保证记录每条连接；RETURN 仅表示命中本脚本来源规则，不等于后续 filter 链最终放行；查看时触发采集，无后台常驻。' 33
        menu_section '查看与设置'
        menu_option 1 '查看操作日志'; menu_option 2 '查看连接日志'
        menu_option 3 '查看操作与连接日志'; menu_option 4 '设置显示条数'
        menu_option 0 '返回主菜单' '2;37'; printf '\n'
        printf '  当前显示条数：%s 行（默认 50）\n' "$lines"
        while :; do
            entry '  请选择 [0-4]：' || return $?
            case $REPLY in 1|2|3|4) break ;; *) error '请输入 0-4' ;; esac
        done
        case $REPLY in
            1) log_show operations "$lines" '查看操作日志' ;;
            2) log_show connections "$lines" '查看连接日志' ;;
            3) log_show both "$lines" '查看操作与连接日志' ;;
            4) log_int '  显示条数 [1-1000；回车保持当前值，0 取消]：' 1 1000 "$lines" && lines=$REPLY ;;
        esac
        rc=$?
        ((rc!=11)) || return 11
    done
}
log_settings_menu() {
    local rc=0 LOG_NOTICE=''
    while :; do
        page '日志轮转与清除设置' back
        [[ -z $LOG_NOTICE ]] || styled "  $LOG_NOTICE" 33
        LOG_NOTICE=''
        logging_show_settings || error '无法读取日志设置，请查看上方后端错误信息'
        styled '  说明：连接日志同上为限速采样；采集在查看时触发，无后台守护。' 33
        printf '  默认值（仅供参考，以上方实际值为准）：操作 on，连接 off，10 MiB，保留 5 份，30 天，限速 10 条/分钟，突发 5，自动轮转 on\n'
        menu_section '日志设置'
        menu_option 1 '操作日志开关（on/off）'; menu_option 2 '连接日志模式（off/deny/all）'
        menu_option 3 '单文件大小上限（MiB，1-100）'; menu_option 4 '保留份数（1-20）'
        menu_option 5 '保留天数（0-365）'; menu_option 6 '连接日志限速（每分钟，1-100）'
        menu_option 7 '连接日志突发（1-100）'; menu_option 8 '自动轮转（on/off）'
        menu_section '轮转与清除'
        menu_option 9 '立即轮转'; menu_option 10 '清除本脚本日志' 31
        menu_option 0 '返回主菜单' '2;37'; printf '\n'
        while :; do
            entry '  请选择 [0-10]：' || return $?
            case $REPLY in 1|2|3|4|5|6|7|8|9|10) break ;; *) error '请输入 0-10' ;; esac
        done
        case $REPLY in
            1) log_word '  新值 [on/off；回车或 0 取消]：' 'on/off' on off && log_apply operations "$REPLY" ;;
            2) log_word '  新模式 [off/deny/all；回车或 0 取消]：' 'off/deny/all' off deny all && log_apply connections "$REPLY" '改连接日志模式会重建受管链，仅新增 LOG 规则，不改变放行或拒绝判定；本页不会自行执行，生效以后端结果为准。' ;;
            3) log_int '  新值 [1-100 MiB；回车或 0 取消]：' 1 100 && log_apply max_mib "$REPLY" ;;
            4) log_int '  新值 [1-20 份；回车或 0 取消]：' 1 20 && log_apply keep "$REPLY" ;;
            5) log_int '  新值 [0-365 天；回车取消，0 为有效值]：' 0 365 && log_apply retention_days "$REPLY" ;;
            6) log_int '  新值 [1-100 条/分钟；回车或 0 取消]：' 1 100 && log_apply rate "$REPLY" ;;
            7) log_int '  新值 [1-100；回车或 0 取消]：' 1 100 && log_apply burst "$REPLY" ;;
            8) log_word '  新值 [on/off；回车或 0 取消]：' 'on/off' on off && log_apply auto_rotate "$REPLY" ;;
            9) log_word '  选择要轮转的日志 [operations/connections/both；回车或 0 取消]：' 'operations/connections/both' operations connections both && log_rotate "$REPLY" ;;
            10) log_word '  选择要清除的日志 [operations/connections/both；回车或 0 取消]：' 'operations/connections/both' operations connections both && log_clear "$REPLY" ;;
        esac
        rc=$?
        ((rc!=11)) || return 11
        case $rc in
            0|2) log_pause || return 11 ;;
            10) [[ -n $LOG_NOTICE ]] || LOG_NOTICE='已取消，未执行任何操作。' ;;
        esac
    done
}
menu() {
    ((EUID==0)) || die '需要 root 权限'
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
                if [[ ! -d $DIR ]]; then STATUS="状态目录不存在：$DIR"
                elif ! MENUWORK=$(mktemp -d "$DIR/.ip-port-allowlist-menu.XXXXXXXX"); then STATUS='无法创建菜单临时目录'
                else ready=1; fi
            else ready=1; fi
        else STATUS='依赖不完整，端口策略操作已停止。请选择 9 检查/安装依赖。'; fi
        if [[ -e $JOURNAL ]]; then
            STATUS='存在未完成的规则更新，请先运行 recover'
        elif ((ready)); then
            if ! menu_state 2> "$MENUWORK/read-error"; then
                broken=1
                STATUS="状态文件损坏：$STATE；请选择 R 进入引导修复"
                [[ ! -s $MENUWORK/read-error ]] || STATUS+=$'\n'"$(cat -- "$MENUWORK/read-error")"
            fi
        fi
        render_main_menu
        NOTICE=''
        local keys='[0-11]'
        ((broken==0)) || keys='[0-11 / R]'
        printf '  请选择 %s：' "$keys"
        IFS= read -r choice || exit 0
        [[ $choice != 0 ]] || exit 0
        if ((broken)) && [[ $choice =~ ^[1-8]$ ]]; then error '状态文件损坏，无法执行该操作；请选择 R 修复状态文件'; continue; fi
        if [[ $choice =~ ^[1-8]$ ]] && ((ready==0)); then error '操作已停止；请先通过菜单 9 完成依赖检查，并确认状态目录存在'; continue; fi
        rc=0
        case $choice in
            1) page '查看端口策略'; menu_cli show || rc=$? ;;
            2) page '设置 / 替换白名单' back; set_menu || rc=$? ;;
            3) page '编辑已有白名单' back; edit_menu || rc=$? ;;
            4) page '取消指定端口限制' back; ports_menu remove || rc=$? ;;
            5) page '清空全部限制' back; clear_menu || rc=$? ;;
            6) page '实际防火墙规则'; menu_cli show --live || rc=$? ;;
            7) page '封锁端口 · 拒绝全部来源' back; ports_menu block || rc=$? ;;
            8) page '设置目标主机地址' back; targets_menu || rc=$? ;;
            9) page '检查 / 安装依赖'; menu_cli doctor --install || rc=$? ;;
            R|r) if ((broken)); then page '状态文件损坏 · 引导修复' back; repair_menu || rc=$?; else styled '  请输入 0-11' 33; fi ;;
            10) logs_menu || rc=$? ;;
            11) log_settings_menu || rc=$? ;;
            *) if ((broken)); then styled '  请输入 0-11，或 R 修复状态文件' 33; else styled '  请输入 0-11' 33; fi ;;
        esac
        ((rc!=11)) || exit 0
        ((rc!=10)) || continue
        ((rc!=130)) || exit 130
        printf '\n  按 Enter 返回主菜单…'; IFS= read -r REPLY || exit 0
    done
}
trap 'printf "\n操作已中断\n" >&2; exit 130' INT TERM
if (($#)); then cli "$@"; else menu; fi
