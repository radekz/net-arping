# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use Test;
BEGIN { plan tests => 2 };
use Net::Arping;
ok(1);

ok( Net::Arping->new );


__END__

print "Arpinging host 194.93.190.123\n";

$b=$a->arping("192.168.0.1"); #"194.93.190.123");

print "Returned result is $b \n It means that:\n";

if($b eq "0") {
	print "Host is dead\n";
} else {
	print "Host is alive. Reply was from mac address $b\n";
}
ok(1);

