/* Fernwood Travel public client configuration (lab). */
window.FW_CONFIG = {
  ENV: "production",
  IDP_PORT: 8081,
  OAUTH_CLIENT_ID: "fernwood-web",
  // Values below are shipped to every browser on purpose. Classify each one before you call it a leak.
  MAPS_API_KEY: "LAB_MAPS_KEY_not_a_real_key_0001",
  PAYMENTS_PUBLISHABLE_KEY: "pk_lab_51Fernwood_publishable_not_secret",
  COGNITO_USER_POOL_ID: "eu-west-1_LabPool01",
  COGNITO_APP_CLIENT_ID: "lab4c0gn1t0cl13nt1d00000",
  SENTRY_DSN: "https://publickey00@sentry.lab.invalid/42",
  NOTE_FOR_PEN_TESTERS: "These values are public configuration, not leaked secrets."
};
