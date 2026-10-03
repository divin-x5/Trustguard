/* ============================================================
   TRUSTGUARD — runtime configuration
   ------------------------------------------------------------
   This is the ONLY file you edit to point the frontend at a
   different backend. It is plain JavaScript (not JSON) so it
   works served straight from disk with no build step.

   HOW IT RESOLVES (see the bottom of app.js):

     1. If API_BASE_URL below is a non-empty string, use it.
     2. Otherwise, auto-detect:
          - page served from localhost  -> http://localhost:8000
          - anything else               -> same origin as the page

   TO DEPLOY TO GITHUB PAGES: paste your deployed backend URL
   into API_BASE_URL below, e.g.

       API_BASE_URL: "https://trustguard-api.onrender.com",

   and leave it as "" to keep local auto-detection.

   RULES
     - Production MUST be https://. GitHub Pages is https, and
       browsers block an https page from calling an http API
       ("mixed content"), so http:// will silently fail.
     - No trailing slash needed; one is stripped automatically.
     - No build step, no bundler, no .env — just edit and redeploy.
   ============================================================ */

window.TRUSTGUARD_CONFIG = {
  // Paste your production API URL here, then redeploy.
  // Examples: "https://trustguard-api.onrender.com"
  // Leave "" for local development.
  API_BASE_URL: "",
};
