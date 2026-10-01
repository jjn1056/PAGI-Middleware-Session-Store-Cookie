package PAGI::Middleware::Session::Store::Cookie;

use strict;
use warnings;

our $VERSION = '0.001005';

use parent 'PAGI::Middleware::Session::Store';
use Future;
use JSON::MaybeXS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256);
use Crypt::AuthEnc::GCM;
use Crypt::PRNG qw(random_bytes);

=head1 NAME

PAGI::Middleware::Session::Store::Cookie - Encrypted client-side session store

=head1 SYNOPSIS

    # As PAGI::Middleware::Session's store (PAGI::Tools 0.002003 or later)
    use PAGI::Compose qw(compose);
    use PAGI::Middleware::Session qw(session_state session_store);
    use PAGI::Routing qw(middleware route);

    my $app = compose(
        middleware => [
            middleware('Session',
                state  => session_state('Cookie',
                    cookie_options => { secure => 1 },    # added to the defaults
                ),
                store  => session_store('Cookie',
                    secret => $ENV{STORE_SECRET},
                ),
                expire => 8 * 3600,    # the server-side idle timeout
            ),
        ],
        routes => [ ... ],
    );

    # The store on its own; all methods return Futures
    use PAGI::Middleware::Session::Store::Cookie;

    my $store = PAGI::Middleware::Session::Store::Cookie->new(
        secret => 'at-least-32-bytes-of-secret-key!',
    );
    my $blob = await $store->set('session_id', { user_id => 123 });
    my $data = await $store->get($blob);
    await $store->delete('session_id');

=head1 DESCRIPTION

Stores session data encrypted in the client cookie itself using AES-256-GCM
(authenticated encryption). No server-side storage is needed.

The C<set> method returns the encrypted blob (not the session ID).
The C<get> method accepts the encrypted blob and returns the decoded
session data, or undef if decryption/verification fails.

B<Limitations:> Cookie size is limited to ~4KB. Large sessions will fail.
Session revocation requires server-side state (e.g., a blocklist).

=head1 USING IT WITH PAGI::Middleware::Session

The store only encrypts and decrypts; L<PAGI::Middleware::Session> decides
when a session is loaded, saved and sent, and its cookie options are where
most of the control is. Handlers read and change the session through
L<PAGI::Session>.

=over 4

=item * B<Use the default cookie state.> The session travels in the value
the middleware's state sends back, and only the cookie state
(L<PAGI::Middleware::Session::State::Cookie>, the default) sends one. The
header-based states never do, so with them nothing persists.

=item * B<The store's secret.> It is the encryption key. Keep it long, random
and the same on every worker; changing it makes every existing session
unreadable, which logs everyone out. (The middleware itself takes no secret.)

=item * B<The cookie.> Its name, attributes (C<Secure> and so on) and
lifetime are configured on L<PAGI::Middleware::Session::State::Cookie>
(C<cookie_name>, C<cookie_options>, C<expire>), passed to the middleware as
C<state>, as the SYNOPSIS does. C<cookie_options> merges into its defaults
(C<HttpOnly>, C<Path=/>, C<SameSite=Lax>), so C<< { secure => 1 } >> is enough
to add C<Secure>.

=item * B<One clock by default.> The middleware's C<expire> (default 3600) is
a server-side idle timeout: it refuses a session whose recorded last access
is older. The cookie itself has no C<Max-Age> unless you give State::Cookie
an C<expire>, so by default it lasts for the browser session.

=item * B<Active readers stay signed in.> With this store the last-access
record travels in the cookie, and a request that only reads the session sends
no new cookie -- until the record is more than half of the middleware's
C<expire> old, when the middleware re-sends the cookie with a fresh one. So a
user idle for longer than C<expire> is signed out, and an active user is not,
whether they read or write.

=item * B<Logout clears one copy.> C<< $session->destroy >> clears the
cookie on the client that asked, but a copy of the old cookie still opens the
session until it expires: nothing on the server can revoke it. If that
matters, use a server-side store.

=back

=cut

sub new {
    my ($class, %args) = @_;
    die "Store::Cookie requires 'secret'" unless $args{secret};

    my $self = $class->SUPER::new(%args);

    # Derive a 32-byte key from the secret via SHA-256
    $self->{_key} = sha256($self->{secret});

    return $self;
}

=head1 METHODS

=head2 new

    my $store = PAGI::Middleware::Session::Store::Cookie->new(
        secret => 'at-least-32-bytes-of-secret-key!',
    );

Creates a new cookie session store. The C<secret> parameter is required
and is used to derive the AES-256 encryption key via SHA-256.

=head2 get

    my $future = $store->get($encrypted_blob);

Decrypts and decodes the blob. Returns a Future resolving to the session
hashref, or undef if the blob is invalid, tampered, or cannot be decoded.

=cut

sub get {
    my ($self, $blob) = @_;

    return Future->done(undef) unless defined $blob && length $blob;

    my $data = eval { $self->_decrypt($blob) };
    return Future->done($data);
}

=head2 set

    my $future = $store->set($id, $data);

Encrypts the session data and returns a Future resolving to the encrypted
blob. This blob is what gets passed to C<State::inject> for storage
in the response cookie. Nothing is stored server-side.

=cut

sub set {
    my ($self, $id, $data) = @_;

    my $blob = $self->_encrypt($data);
    return Future->done($blob);
}

=head2 delete

    my $future = $store->delete($id);

No-op for cookie stores (client manages cookie lifetime).
Returns a Future resolving to 1.

=cut

sub delete {
    my ($self, $id) = @_;
    return Future->done(1);
}

sub _encrypt {
    my ($self, $data) = @_;

    my $json = encode_json($data);

    # Generate random 12-byte IV (standard for AES-GCM)
    my $iv = random_bytes(12);

    my $gcm = Crypt::AuthEnc::GCM->new('AES', $self->{_key}, $iv);
    my $ciphertext = $gcm->encrypt_add($json);
    my $tag = $gcm->encrypt_done;

    # Pack: iv (12) + tag (16) + ciphertext
    my $packed = $iv . $tag . $ciphertext;
    return encode_base64($packed, '');
}

sub _decrypt {
    my ($self, $blob) = @_;

    my $packed = decode_base64($blob);
    return undef unless defined $packed && length($packed) > 28;

    # Unpack: iv (12) + tag (16) + ciphertext
    my $iv         = substr($packed, 0, 12);
    my $tag        = substr($packed, 12, 16);
    my $ciphertext = substr($packed, 28);

    my $gcm = Crypt::AuthEnc::GCM->new('AES', $self->{_key}, $iv);
    my $json = $gcm->decrypt_add($ciphertext);
    my $valid = $gcm->decrypt_done($tag);

    return undef unless $valid;

    return decode_json($json);
}

1;

__END__

=head1 SECURITY

Session data is encrypted with AES-256-GCM, which provides both
confidentiality (data cannot be read) and authenticity (data cannot
be tampered with). The encryption key is derived from the C<secret>
via SHA-256.

Each encryption uses a random 12-byte IV, so the same session data
produces different ciphertext each time.

=head2 IV Generation

The encryption initialization vector (IV) is generated from
L<Crypt::PRNG>, which uses system sources of randomness such as
F</dev/urandom> as a seed.

=head2 Cookie Size

HTTP cookies are limited to approximately 4KB by most browsers.
Large session data will produce cookies that exceed this limit and
be silently rejected by the browser. Keep session data small.

=head1 AUTHORS

John Napiorkowski

OpenAI Codex

Anthropic Claude

=head1 LICENSE

This software is Copyright (c) 2026 by John Napiorkowski.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

For the full license text, see:

L<https://www.perlfoundation.org/artistic-license-20.html>

=head1 SEE ALSO

L<PAGI::Middleware::Session> - Session management middleware (its STATE CLASSES
and STORE CLASSES sections)

L<PAGI::Session> - The helper handlers use to read and change the session

L<PAGI::Middleware::Session::Store> - Base store interface

=cut
