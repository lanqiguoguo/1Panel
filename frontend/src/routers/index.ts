import router from '@/routers/router';
import NProgress from '@/config/nprogress';
import { GlobalStore } from '@/store';
import { AxiosCanceler } from '@/api/helper/axios-cancel';

const axiosCanceler = new AxiosCanceler();

interface SessionCheckResponse {
    code?: number;
    data?: {
        securityEntrance?: string;
    };
}

const sessionCheckUrl = `${String(import.meta.env.VITE_API_URL || '/api/v1').replace(/\/+$/, '')}/settings/search`;
let sessionCheckPromise: Promise<SessionCheckResponse | null> | null = null;

const checkServerSession = (): Promise<SessionCheckResponse | null> => {
    if (!sessionCheckPromise) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 5000);

        sessionCheckPromise = fetch(sessionCheckUrl, {
            method: 'POST',
            credentials: 'include',
            cache: 'no-store',
            signal: controller.signal,
        })
            .then(async (response) => {
                if (!response.ok) return null;
                return (await response.json()) as SessionCheckResponse;
            })
            .catch(() => null)
            .finally(() => {
                window.clearTimeout(timeout);
                sessionCheckPromise = null;
            });
    }
    return sessionCheckPromise;
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

    const session = await checkServerSession();
    const isAuthenticated = session?.code === 200;
    const requiresAuth = to.matched.some((record) => record.meta.requiresAuth);

    // isLogin is persisted for UI state only and can be changed by the client.
    // Always make navigation decisions from the server-backed session result.
    globalStore.setLogStatus(isAuthenticated);
    if (isAuthenticated && session?.data?.securityEntrance !== undefined) {
        globalStore.entrance = session.data.securityEntrance;
    }

    if (!isAuthenticated && (requiresAuth || to.name !== 'entrance')) {
        next({
            name: 'entrance',
            params: to.params,
        });
        NProgress.done();
        return;
    }
    if (to.name === 'entrance' && isAuthenticated) {
        if (to.params.code === globalStore.entrance) {
            next({
                name: 'home',
            });
            NProgress.done();
            return;
        }
        next({ name: '404' });
        NProgress.done();
        return;
    }

    return next();
});

router.afterEach(() => {
    NProgress.done();
});

export default router;
