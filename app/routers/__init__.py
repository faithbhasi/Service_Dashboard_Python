"""Every API router, in the order they are mounted. The endpoint-authorization test walks this list."""
from . import ad, admin, auth, dashboard, health, logs, personalization, search, settings

ALL_ROUTERS = [health.router, auth.router, auth.oidc_router, settings.router, personalization.router, logs.router, admin.router,
               dashboard.router, search.router, ad.router]
