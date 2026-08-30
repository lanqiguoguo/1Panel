import router from '@/routers/router';
import NProgress from '@/config/nprogress';
import { GlobalStore } from '@/store';
import { AxiosCanceler } from '@/api/helper/axios-cancel';

const axiosCanceler = new AxiosCanceler();

export type AuthState = 'authenticated' | 'unauthenticated' | 'unknown';

export interface SessionCheckResponse {
    code?: number;
    data?: {
        securityEntrance?: string;
    };
}

export interface ResolvedSession {
    auth: AuthState;
    securityEntrance?: string;
}

export const isUnauthenticated = (session: SessionCheckResponse | null): boolean => session?.code === 401;

export const resolveAuthState = (session: SessionCheckResponse | null): AuthState => {
    if (session && session.code === 200) return 'authenticated';
    if (isUnauthenticated(session)) return 'unauthenticated';
    return 'unknown';
};

export const resolveSession = (session: SessionCheckResponse | null): ResolvedSession => ({
    auth: resolveAuthState(session),
    securityEntrance: session?.data?.securityEntrance,
});

export interface GuardRoute {
    name?: unknown;
    params?: Record<string, unknown>;
    matched: { meta: { requiresAuth?: boolean } }[];
}

export const requiresAuthOf = (to: GuardRoute): boolean =>
    to.matched.some((record) => record.meta.requiresAuth === true);

const entranceName = 'entrance';

export const shouldRedirect = (to: GuardRoute, auth: AuthState): boolean =>
    auth === 'unauthenticated' && (requiresAuthOf(to) || to.name !== entranceName);

const sessionCheckUrl = `${String(import.meta.env.VITE_API_URL || '/api/v1').replace(/\/+$/, '')}/settings/search`;
const SESSION_TTL = 30_000;

interface SessionCacheEntry {
    session: ResolvedSession;
    updatedAt: number;
}

let sessionCache: SessionCacheEntry | null = null;
let sessionCheckPromise: Promise<ResolvedSession> | null = null;

export const clearSessionCache = (): void => {
    sessionCache = null;
};

const checkServerSession = async (): Promise<ResolvedSession> => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);

    try {
        const response = await fetch(sessionCheckUrl, {
            method: 'POST',
            credentials: 'include',
            cache: 'no-store',
            signal: controller.signal,
        });
        if (response.status === 401) {
            return { auth: 'unauthenticated' };
        }
        const body = (await response.json()) as SessionCheckResponse;
        return resolveSession(body);
    } catch {
        return { auth: 'unknown' };
    } finally {
        window.clearTimeout(timeout);
    }
};

const refreshServerSession = (): void => {
    if (sessionCheckPromise) return;
    sessionCheckPromise = checkServerSession().then((session) => {
        sessionCache = { session, updatedAt: Date.now() };
        return session;
    });
    sessionCheckPromise.finally(() => {
        sessionCheckPromise = null;
    });
};

export const getServerSession = async (publicRoute: boolean): Promise<ResolvedSession> => {
    if (publicRoute) {
        // Public pages never need the server session for navigation decisions.
        return { auth: 'unknown' };
    }
    // Serve a fresh non-logged-out snapshot without touching the network.
    // An expired snapshot is refreshed in the background so navigation never
    // blocks on the network again.
    if (sessionCache && sessionCache.session.auth !== 'unauthenticated') {
        if (Date.now() - sessionCache.updatedAt < SESSION_TTL) {
            return sessionCache.session;
        }
        refreshServerSession();
        return sessionCache.session;
    }
    // No cache yet, or the cached session is a logged-out snapshot that a
    // fresh login may have just invalidated: re-check on the spot.
    if (sessionCheckPromise) return sessionCheckPromise;
    sessionCheckPromise = checkServerSession().then((session) => {
        sessionCache = { session, updatedAt: Date.now() };
        return session;
    });
    try {
        return await sessionCheckPromise;
    } finally {
        sessionCheckPromise = null;
    }
};

router.beforeEach(async (to, from, next) => {
    NProgress.start();
    axiosCanceler.removeAllPending();
    const globalStore = GlobalStore();

    if (globalStore.isIntl && to.path.includes('/xpack/alert')) {
        next({ name: '404' });
        NProgress.done();
        return;
    }

    const publicRoute = !requiresAuthOf(to);
    if (publicRoute) {
        // Public pages (entrance/login/404/...) never block on the network.
        // The entrance page keeps its convenience bounce using the persisted
        // local login state only: no request is sent, and a transient server
        // failure can never force a logout or a redirect loop.
        if (to.name === entranceName && globalStore.isLogin) {
            if (to.params && to.params.code === globalStore.entrance) {
                next({ name: 'home' });
                NProgress.done();
                return;
            }
            next({ name: '404' });
            NProgress.done();
            return;
        }
        return next();
    }

    const { auth, securityEntrance } = await getServerSession(false);

    // isLogin is persisted for UI state only and can be changed by the client.
    // Keep it derived from the latest server-backed session result; a transient
    // failure (unknown) must not log the user out, so leave the previous value.
    if (auth === 'authenticated') {
        globalStore.setLogStatus(true);
        if (securityEntrance !== undefined) {
            globalStore.entrance = securityEntrance;
        }
    } else if (auth === 'unauthenticated') {
        globalStore.setLogStatus(false);
    }

    if (shouldRedirect(to, auth)) {
        next({
            name: 'entrance',
            params: to.params,
        });
        NProgress.done();
        return;
    }

    return next();
});

router.afterEach(() => {
    NProgress.done();
});

export default router;
