# frozen_string_literal: true
#
# Noble fork-only addition. Copy into the Fizzy fork at:
#   app/controllers/sso_controller.rb
#
# Verified against Fizzy source 2026-05-16 (Identity/Session model,
# Authentication concern). Trusts a short-lived HMAC token minted by
# NobleCore (see noblecore/src/lib/fizzy-sso.ts). Token format:
#   base64url(JSON payload) + "." + base64url(HMAC_SHA256(payload, secret))
# payload = { "email": ..., "name": ..., "iat": ..., "exp": ... }
#
# Shared secret: ENV["FIZZY_SSO_SECRET"] (must equal NobleCore's).
#
# Reuses Fizzy's own session machinery:
#   - Identity.find_or_create_by!(email_address:)  (Identity model)
#   - start_new_session_for(identity)              (Authentication concern,
#       sets the signed session_token cookie exactly like magic-link login)
# and ensures the identity has a User membership in the single account so
# the user lands inside the app rather than the "no accounts" screen.

require "openssl"
require "base64"
require "json"

class SsoController < ApplicationController
  # /sso runs before auth + before an account is resolved.
  skip_before_action :require_account, raise: false
  skip_before_action :require_authentication, raise: false
  skip_forgery_protection

  def show  = authenticate_and_redirect
  def create = authenticate_and_redirect

  private

  def authenticate_and_redirect
    payload = verify_token(params[:token].to_s)
    return head(:unauthorized) unless payload

    email = payload["email"].to_s.strip.downcase
    return head(:unauthorized) if email.empty?

    identity = Identity.find_or_create_by!(email_address: email)
    ensure_membership(identity, payload["name"].to_s.presence || email)

    start_new_session_for(identity) # Authentication concern: creates Session + signed cookie

    redirect_to safe_return_to, allow_other_host: false
  end

  # Single-tenant install: attach the identity to the one account if it
  # isn't already a member, so SSO'd teammates land straight in.
  def ensure_membership(identity, name)
    account = Account.first
    return unless account
    return if account.users.exists?(identity: identity)

    account.users.create!(
      identity: identity,
      name: name,
      role: :member,
      verified_at: Time.current
    )
  end

  # ── Token verification (self-contained) ───────────────────────────
  def verify_token(token)
    secret = ENV["FIZZY_SSO_SECRET"].to_s
    return nil if secret.empty?

    p_b64, sig_b64 = token.split(".", 2)
    return nil unless p_b64 && sig_b64

    expected = b64url(OpenSSL::HMAC.digest("SHA256", secret, p_b64))
    return nil unless ActiveSupport::SecurityUtils.secure_compare(expected, sig_b64)

    payload = JSON.parse(Base64.urlsafe_decode64(pad(p_b64)))
    return nil if payload["exp"].to_i < Time.now.to_i

    payload
  rescue StandardError
    nil
  end

  def b64url(bin) = Base64.urlsafe_encode64(bin).delete("=")
  def pad(str)    = str + "=" * ((4 - str.length % 4) % 4)

  def safe_return_to
    rt = params[:return_to].to_s
    rt.start_with?("/") && !rt.start_with?("//") ? rt : "/"
  end
end
