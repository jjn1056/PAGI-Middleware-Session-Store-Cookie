#!/usr/bin/env perl
#
# A visit counter whose session lives entirely in an encrypted cookie: no
# server-side storage, so any worker can serve any request and the count
# survives a restart.
#
# Needs PAGI::Tools 0.002003 or later (PAGI::Compose, PAGI::Routing).
#
# Run:
#   pagi-server --app examples/counter.pl --port 5000
#
# Test:
#   curl -c cookies.txt -b cookies.txt http://localhost:5000/
#   curl -c cookies.txt -b cookies.txt http://localhost:5000/
#   curl -c cookies.txt -b cookies.txt http://localhost:5000/reset
#
use strict;
use warnings;

use PAGI::Compose qw(compose);
use PAGI::Middleware::Session qw(session_store);
use PAGI::Response qw(text_response);
use PAGI::Routing qw(middleware route);
use PAGI::Session qw(session);

sub count {
    my ($request) = @_;
    my $session = session($request);
    $session->set(count => $session->get('count', 0) + 1);
    return text_response("Visit #" . $session->get('count') . "\n");
}

sub reset_session {
    my ($request) = @_;
    session($request)->destroy;
    return text_response("Session destroyed. Visit / to start fresh.\n");
}

# The store's secret encrypts the cookie: keep it long, random and the same
# on every worker, and load it from configuration in a real app.
compose(
    middleware => [
        middleware('Session',
            store  => session_store('Cookie',
                secret => 'change-me-store-secret-at-least-32-bytes',
            ),
        ),
    ],
    routes => [
        route('/'      => \&count),
        route('/reset' => \&reset_session),
    ],
);
