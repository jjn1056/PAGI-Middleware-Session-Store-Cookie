use strict;
use warnings;

# The clock the middleware reads, so expiry can be tested without sleeping.
our $NOW;
BEGIN { *CORE::GLOBAL::time = sub () { defined $main::NOW ? $main::NOW : CORE::time() } }

use Test2::V0;
use Future::AsyncAwait;
use PAGI::Middleware::Session;
use PAGI::Middleware::Session::Store::Cookie;

# How PAGI::Middleware::Session behaves with this store, as the POD
# ("USING IT WITH PAGI::Middleware::Session") describes it.

my $SECRET = 'at-least-32-bytes-of-secret-key!';

sub run_async { my ($code) = @_; my $f = $code->(); $f->get if $f; return }

# One request through the middleware. $handler receives the session hashref
# and may change it; returns the Set-Cookie header (or undef) and the
# session the handler saw.
sub request {
    my ($middleware, $cookie, $handler) = @_;
    my (@events, %seen);
    my $app = async sub {
        my ($scope, $receive, $send) = @_;
        %seen = %{ $scope->{'pagi.session'} };
        $handler->($scope->{'pagi.session'}) if $handler;
        await $send->({ type => 'http.response.start', status => 200, headers => [] });
        await $send->({ type => 'http.response.body', body => 'OK', more => 0 });
    };
    my $scope = {
        type    => 'http',
        method  => 'GET',
        path    => '/',
        headers => defined $cookie ? [['Cookie', "pagi_session=$cookie"]] : [],
    };
    run_async sub {
        $middleware->wrap($app)->($scope, async sub { {} }, async sub { push @events, $_[0] });
    };
    my ($set) = map { $_->[1] } grep { lc($_->[0]) eq 'set-cookie' } @{ $events[0]{headers} };
    my ($blob) = defined $set ? $set =~ /pagi_session=([^;]*)/ : ();
    return ($set, $blob, \%seen);
}

sub session_mw {
    return PAGI::Middleware::Session->new(
        store  => PAGI::Middleware::Session::Store::Cookie->new(secret => $SECRET),
        @_,
    );
}

subtest 'an active reader keeps the session: the cookie is re-sent past half of expire' => sub {
    my $mw = session_mw(expire => 10);

    local $NOW = 1_000;
    my (undef, $written) = request($mw, undef, sub { $_[0]{user} = 'ada' });
    ok($written, 'a change sends the session in a new cookie');

    local $NOW = 1_004;
    my ($set, undef, $seen) = request($mw, $written);
    is($seen->{user}, 'ada', 'a read finds the session');
    is($set, undef, 'and before half of expire sends no new cookie');

    local $NOW = 1_006;
    my (undef, $refreshed) = request($mw, $written);
    ok($refreshed && $refreshed ne $written,
        'past half of expire a read re-sends the session with its new last access');

    local $NOW = 1_012;
    (undef, undef, $seen) = request($mw, $refreshed);
    is($seen->{user}, 'ada', '12s after the change the reader is still signed in');

    (undef, undef, $seen) = request($mw, $written);
    is($seen->{user}, undef, 'while a copy of the cookie nobody refreshed has expired');
};

subtest 'destroy clears the cookie on that client only' => sub {
    my $mw = session_mw();
    my (undef, $cookie) = request($mw, undef, sub { $_[0]{user} = 'ada' });

    my ($set) = request($mw, $cookie, sub { $_[0]{_destroyed} = 1 });
    like($set, qr/pagi_session=;|Max-Age=0|Expires=Thu, 01 Jan 1970/i,
        'the destroying response clears the cookie');

    my (undef, undef, $seen) = request($mw, $cookie);
    is($seen->{user}, 'ada', 'but a copy of the old cookie still opens the session');
};

done_testing;
