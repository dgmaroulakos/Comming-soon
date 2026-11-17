<?php
/**
 * Plugin Name: Coming Soon Password
 * Description: Custom HTML coming-soon page with shared password access.
 * Version: 1.0.0
 * Requires at least: 6.8
 * Requires PHP: 7.4
 */

namespace ComingSoonPassword;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const OPTION = 'coming_soon_password_settings';
const PAGE = 'coming-soon-password';
const FORM_MARKER = '<!-- coming-soon-access-form -->';
const ACCESS_DURATION = 12 * HOUR_IN_SECONDS;

function settings(): array {
	return (array) get_option( OPTION, array() ) + array(
		'enabled'       => false,
		'html'          => '',
		'password_hash' => '',
	);
}

function register_settings(): void {
	register_setting( PAGE, OPTION );
	add_filter( 'pre_update_option_' . OPTION, __NAMESPACE__ . '\sanitize_settings', 10, 2 );
}

function sanitize_settings( $input, $old_value ): array {
	$previous = (array) $old_value + settings();
	if ( ! is_array( $input ) || ! current_user_can( 'manage_options' ) ) {
		return $previous;
	}

	$next = $previous;
	$next['enabled'] = ! empty( $input['enabled'] );
	if ( current_user_can( 'unfiltered_html' ) && isset( $input['html'] ) && is_string( $input['html'] ) ) {
		$next['html'] = trim( $input['html'] );
	}

	$password = $input['password'] ?? '';
	if ( '' !== $password ) {
		if ( ! is_string( $password ) || strlen( $password ) < 6 || strlen( $password ) > 256 || trim( $password ) !== $password ) {
			add_settings_error( OPTION, 'invalid_password', 'Ο κωδικός πρέπει να έχει 6 έως 256 bytes και να μην έχει κενά στην αρχή ή στο τέλος.' );
			return $previous;
		}
		$next['password_hash'] = wp_hash_password( $password );
	}

	if ( $next['enabled'] && '' === $next['password_hash'] ) {
		add_settings_error( OPTION, 'missing_password', 'Ορίστε κωδικό πρόσβασης για να ενεργοποιήσετε τη σελίδα Coming Soon.' );
		return $previous;
	}

	return $next;
}

function add_settings_page(): void {
	add_options_page( 'Coming Soon', 'Coming Soon', 'manage_options', PAGE, __NAMESPACE__ . '\render_settings' );
}

function render_settings(): void {
	$config = settings();
	?>
	<div class="wrap">
		<h1>Coming Soon</h1>
		<form action="options.php" method="post">
			<?php settings_fields( PAGE ); ?>
			<p>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[enabled]" value="1" <?php checked( $config['enabled'] ); ?>>
					Ενεργοποίηση σελίδας Coming Soon
				</label>
			</p>
			<p>
				<label for="csp-password"><strong>Κωδικός πρόσβασης</strong></label><br>
				<input type="password" id="csp-password" name="<?php echo esc_attr( OPTION ); ?>[password]" class="regular-text" autocomplete="new-password">
			</p>
			<p class="description">Αφήστε το πεδίο κενό για να διατηρήσετε τον υπάρχοντα κωδικό.</p>
			<?php if ( current_user_can( 'unfiltered_html' ) ) : ?>
				<p><label for="csp-html"><strong>HTML σελίδας</strong></label></p>
				<textarea id="csp-html" name="<?php echo esc_attr( OPTION ); ?>[html]" class="large-text code" rows="16" spellcheck="false"><?php echo esc_textarea( $config['html'] ); ?></textarea>
				<p class="description">Επικολλήστε HTML ή αφήστε το πεδίο κενό για την προεπιλεγμένη σελίδα. Για να ορίσετε τη θέση της φόρμας, προσθέστε <code><?php echo esc_html( FORM_MARKER ); ?></code> μέσα στο HTML.</p>
			<?php endif; ?>
			<?php submit_button(); ?>
		</form>
	</div>
	<?php
}

function cookie_name(): string {
	return 'csp_access_' . COOKIEHASH . '_' . get_current_blog_id();
}

function access_token( int $expires, string $password_hash ): string {
	$signature = hash_hmac( 'sha256', cookie_name() . ':' . $expires . ':' . $password_hash, wp_salt( 'auth' ) );
	return $expires . '.' . $signature;
}

function has_access( array $config ): bool {
	if ( current_user_can( 'manage_options' ) ) {
		return true;
	}

	$cookie = $_COOKIE[ cookie_name() ] ?? '';
	if ( '' === $config['password_hash'] || ! is_string( $cookie ) || ! preg_match( '/\A([0-9]{1,12})\.[a-f0-9]{64}\z/', $cookie, $matches ) ) {
		return false;
	}

	$expires = (int) $matches[1];
	return $expires > time() && hash_equals( access_token( $expires, $config['password_hash'] ), $cookie );
}

function disable_page_cache(): void {
	if ( settings()['enabled'] && ! defined( 'DONOTCACHEPAGE' ) ) {
		define( 'DONOTCACHEPAGE', true );
	}
}

function gate_rest( $result ) {
	$config = settings();
	if ( ! $config['enabled'] ) {
		return $result;
	}
	nocache_headers();
	if ( null !== $result && is_wp_error( $result ) ) {
		return $result;
	}
	if ( has_access( $config ) ) {
		return $result;
	}
	return new \WP_Error( 'csp_locked', 'Απαιτείται κωδικός πρόσβασης.', array( 'status' => 403 ) );
}

function gate_admin(): void {
	$config = settings();
	if ( ! $config['enabled'] || has_access( $config ) ) {
		return;
	}
	nocache_headers();
	if ( wp_doing_ajax() || 'admin-post.php' === ( $GLOBALS['pagenow'] ?? '' ) ) {
		wp_die( 'Απαιτείται κωδικός πρόσβασης.', '', array( 'response' => 403 ) );
	}
	wp_safe_redirect( home_url( '/' ) );
	exit;
}

function gate_frontend(): void {
	$config = settings();
	if ( ! $config['enabled'] ) {
		return;
	}
	nocache_headers();
	if ( has_access( $config ) ) {
		return;
	}

	$attempted = 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && isset( $_POST['csp_access_password'] );
	$password = $attempted && is_string( $_POST['csp_access_password'] ) ? wp_unslash( $_POST['csp_access_password'] ) : '';
	if ( '' !== $password && strlen( $password ) <= 256 && wp_check_password( $password, $config['password_hash'] ) ) {
		$expires = time() + ACCESS_DURATION;
		if ( setcookie( cookie_name(), access_token( $expires, $config['password_hash'] ), array(
			'expires'  => $expires,
			'path'     => '/',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		) ) ) {
			wp_safe_redirect( home_url( '/' ), 303 );
			exit;
		}
	}

	status_header( 503 );
	header( 'Content-Type: text/html; charset=UTF-8' );
	header( 'X-Robots-Tag: noindex, nofollow', true );
	render_landing_page( $config['html'], $attempted );
	exit;
}

function render_landing_page( string $html, bool $attempted ): void {
	ob_start();
	?>
	<form method="post" action="<?php echo esc_url( home_url( '/' ) ); ?>" class="csp-access-form">
		<?php if ( $attempted ) : ?>
			<p role="alert">Η πρόσβαση δεν ήταν δυνατή. Ελέγξτε τον κωδικό και δοκιμάστε ξανά.</p>
		<?php endif; ?>
		<label for="csp-access-password">Κωδικός πρόσβασης</label>
		<input type="password" id="csp-access-password" name="csp_access_password" autocomplete="current-password" required>
		<button type="submit">Είσοδος</button>
	</form>
	<?php
	$form = ob_get_clean();

	if ( '' === $html ) {
		$html = '<!doctype html><html lang="el"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Coming Soon</title></head><body><main><h1>Σύντομα κοντά σας</h1>' . FORM_MARKER . '</main></body></html>';
	}
	if ( false !== strpos( $html, FORM_MARKER ) ) {
		$parts = explode( FORM_MARKER, $html, 2 );
		echo $parts[0] . $form . $parts[1];
		return;
	}

	$body_end = strripos( $html, '</body>' );
	echo false === $body_end ? $html . $form : substr_replace( $html, $form, $body_end, 0 );
}

add_action( 'admin_init', __NAMESPACE__ . '\register_settings' );
add_action( 'admin_init', __NAMESPACE__ . '\gate_admin', 0 );
add_action( 'admin_menu', __NAMESPACE__ . '\add_settings_page' );
add_action( 'plugins_loaded', __NAMESPACE__ . '\disable_page_cache', 0 );
add_action( 'template_redirect', __NAMESPACE__ . '\gate_frontend', -100 );
add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\gate_rest', 110 );
