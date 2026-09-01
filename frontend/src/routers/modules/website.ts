import { Layout } from '@/routers/constant';

const webSiteRouter = {
    sort: 3,
    path: '/websites',
    component: Layout,
    redirect: '/websites',
    meta: {
        icon: 'p-website',
        title: 'menu.website',
    },
    children: [
        {
            path: '/websites',
            name: 'Website',
            component: () => import('@/views/website/website/index.vue'),
            meta: {
                title: 'menu.website',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/:id/config/:tab',
            name: 'WebsiteConfig',
            component: () => import('@/views/website/website/config/index.vue'),
            hidden: true,
            props: true,
            meta: {
                activeMenu: '/websites',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/ssl',
            name: 'SSL',
            component: () => import('@/views/website/ssl/index.vue'),
            meta: {
                title: 'menu.ssl',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/php',
            name: 'PHP',
            component: () => import('@/views/website/runtime/php/index.vue'),
            meta: {
                title: 'menu.runtime',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/node',
            name: 'Node',
            hidden: true,
            component: () => import('@/views/website/runtime/node/index.vue'),
            meta: {
                activeMenu: '/websites/runtimes/php',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/java',
            name: 'java',
            hidden: true,
            component: () => import('@/views/website/runtime/java/index.vue'),
            meta: {
                activeMenu: '/websites/runtimes/php',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/go',
            name: 'go',
            hidden: true,
            component: () => import('@/views/website/runtime/go/index.vue'),
            meta: {
                activeMenu: '/websites/runtimes/php',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/python',
            name: 'python',
            hidden: true,
            component: () => import('@/views/website/runtime/python/index.vue'),
            meta: {
                activeMenu: '/websites/runtimes/php',
                requiresAuth: true,
            },
        },
        {
            path: '/websites/runtimes/dotnet',
            name: 'dotNet',
            hidden: true,
            component: () => import('@/views/website/runtime/dotnet/index.vue'),
            meta: {
                activeMenu: '/websites/runtimes/php',
                requiresAuth: true,
            },
        },
    ],
};

export default webSiteRouter;
