# OAuth consent callback CSP fix

- Allow the validated OAuth callback origin in the consent page's `form-action`
  policy so browsers can complete the POST redirect chain.
- Keep the policy transaction-specific and fall back to same-origin only for an
  invalid callback.
- Add regression coverage, run the OAuth tests and full Docker test target, then
  deploy and verify the live service.
