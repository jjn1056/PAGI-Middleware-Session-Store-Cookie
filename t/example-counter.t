use strict;
use warnings;
use Test2::V0;
use FindBin qw($Bin);

# examples/counter.pl: a visit counter whose session lives entirely in the
# encrypted cookie, with /reset destroying it.

eval { require PAGI::Compose; require PAGI::Test::Client; 1 }
    or skip_all 'the example needs PAGI::Tools 0.002003 or later';

my $app = do "$Bin/../examples/counter.pl";
is($@, '', 'the example loads');

my $client = PAGI::Test::Client->new(app => $app);
is($client->get('/')->text, "Visit #1\n", 'the first visit');
is($client->get('/')->text, "Visit #2\n", 'the count travels in the cookie');
like($client->get('/reset')->text, qr/Session destroyed/, '/reset destroys the session');
is($client->get('/')->text, "Visit #1\n", 'and the count starts over');

done_testing;
