# Noble fork-only: allow NobleCore to embed Fizzy in the /boards-2.0 iframe.
# See docs/fizzy/fork-patches.md.
#
# Fizzy's config/initializers/content_security_policy.rb owns the real CSP
# (Rails policy DSL) and reads extra frame-ancestors from ENV
# "CSP_FRAME_ANCESTORS" — so the iframe allow-listing is done via that env
# var, NOT here. This file only defensively drops X-Frame-Options in case
# a SAMEORIGIN default is present (CSP frame-ancestors supersedes it in
# modern browsers, but belt-and-suspenders).
Rails.application.config.action_dispatch.default_headers.delete("X-Frame-Options")
