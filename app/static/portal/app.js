/* Fernwood Travel web client - build 2026.10.3 (lab target, intentionally vulnerable) */
(function () {
  "use strict";

  var CFG = window.FW_CONFIG || {};
  var IDP = location.protocol + "//" + location.hostname + ":" + (CFG.IDP_PORT || 8081);

  var API = {
    me: "/api/me",
    login: "/api/login",
    loginSso: "/api/login/sso",
    bookings: "/api/v2/bookings",
    booking: function (ref) { return "/api/v2/bookings/" + encodeURIComponent(ref); },
    invoice: function (ref) { return "/api/v2/bookings/" + encodeURIComponent(ref) + "/invoice"; },
    // Ops dashboard only - not linked from the customer UI yet.
    featureFlags: "/api/v2/internal/feature-flags"
  };

  // Booking references look like BK-10042.
  var BOOKING_REF = /^BK-\d{5}$/;

  function $(sel) { return document.querySelector(sel); }

  function getJSON(url, opts) {
    opts = opts || {};
    opts.credentials = "same-origin";
    opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    return fetch(url, opts).then(function (r) {
      return r.json().then(function (body) { return { status: r.status, body: body }; });
    });
  }

  /* ------------------------------------------------------------ redirects */
  // Only allow redirects that stay on Fernwood.
  function getSafeRedirect(target) {
    if (target && (target.startsWith("/") ||
        (target.startsWith("http") && target.startsWith(window.location.origin)))) {
      return target;
    }
    return "/account/profile";
  }

  function nextParam() {
    return new URLSearchParams(location.search).get("next");
  }

  /* ---------------------------------------------------------------- login */
  function initLogin() {
    var form = $("#login-form");
    if (!form) return;

    // Already signed in? Skip the form and continue to where the user was going.
    getJSON(API.me).then(function (r) {
      if (r.status === 200) location.href = getSafeRedirect(nextParam());
    });

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var data = { username: form.username.value, password: form.password.value };
      getJSON(API.login, { method: "POST", body: JSON.stringify(data) }).then(function (r) {
        if (r.status === 200) {
          location.href = getSafeRedirect(nextParam());
        } else {
          $("#login-error").textContent = r.body.error || "Login failed";
        }
      });
    });

    var sso = $("#sso-button");
    if (sso) sso.addEventListener("click", startSso);
  }

  /* ------------------------------------------------------------------ SSO */
  function startSso() {
    var state = Math.random().toString(36).slice(2);
    sessionStorage.setItem("fw_oauth_state", state);
    var params = new URLSearchParams({
      response_type: "code",
      client_id: CFG.OAUTH_CLIENT_ID || "fernwood-web",
      redirect_uri: location.origin + "/callback",
      scope: "openid profile",
      state: state
    });
    location.href = IDP + "/oauth/authorize?" + params.toString();
  }

  function finishSso() {
    var status = $("#sso-status");
    if (!status) return;
    var p = new URLSearchParams(location.search);
    if (p.get("state") !== sessionStorage.getItem("fw_oauth_state")) {
      status.textContent = "State mismatch - please start again.";
      return;
    }
    var form = new URLSearchParams({
      grant_type: "authorization_code",
      code: p.get("code") || "",
      client_id: CFG.OAUTH_CLIENT_ID || "fernwood-web",
      redirect_uri: location.origin + "/callback"
    });
    fetch(IDP + "/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString()
    }).then(function (r) { return r.json(); }).then(function (tok) {
      if (!tok.access_token) throw new Error(tok.error || "token exchange failed");
      return getJSON(API.loginSso, { method: "POST", body: JSON.stringify({ access_token: tok.access_token }) });
    }).then(function (r) {
      if (r.status === 200) location.href = "/account/profile";
      else status.textContent = r.body.error || "Sign-in failed";
    }).catch(function (err) { status.textContent = String(err); });
  }

  /* ------------------------------------------------------------- bookings */
  function renderBookings() {
    var table = $("#bookings");
    if (!table) return;
    getJSON(API.bookings).then(function (r) {
      var rows = (r.body.bookings || []).map(function (b) {
        return "<tr><td>" + b.ref + "</td><td>" + b.route + "</td><td>" + b.travel_date + "</td>" +
          "<td><a href='" + API.booking(b.ref) + "'>details</a> &middot; " +
          "<a href='" + API.invoice(b.ref) + "'>invoice</a></td></tr>";
      });
      table.innerHTML = "<tr><th>Ref</th><th>Route</th><th>Date</th><th></th></tr>" +
        (rows.join("") || "<tr><td colspan=4 class=muted>No bookings yet.</td></tr>");
    });
  }

  function initBookings() {
    var form = $("#booking-form");
    if (!form) return;
    renderBookings();
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var data = { route: form.route.value, travel_date: form.travel_date.value };
      getJSON(API.bookings, { method: "POST", body: JSON.stringify(data) }).then(renderBookings);
    });
  }

  /* ------------------------------------------------------------- language */
  // After switching language, send the user back where they were -
  // but never to another website ("external links start with http").
  function initLanguageSwitch() {
    if (!$("#lang-status")) return;
    var back = new URLSearchParams(location.search).get("return") || "/";
    if (/^https?:/i.test(back)) back = "/";
    setTimeout(function () { location.href = back; }, 800);
  }

  // Ops-only helper kept for the upcoming admin dashboard. Not called anywhere yet.
  function loadFeatureFlags() {
    return getJSON(API.featureFlags).then(function (r) { return r.body.flags; });
  }

  function isBookingRef(value) { return BOOKING_REF.test(value); }

  window.Fernwood = { version: "2026.10.3", isBookingRef: isBookingRef, _flags: loadFeatureFlags };

  document.addEventListener("DOMContentLoaded", function () {
    initLogin();
    finishSso();
    initBookings();
    initLanguageSwitch();
  });
})();
