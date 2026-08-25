import { GlobalStore } from '@/store';

export const useTheme = () => {
    const switchTheme = () => {
        const globalStore = GlobalStore();
        const themeConfig = globalStore.themeConfig;
        let itemTheme = themeConfig.theme;
        if (itemTheme === 'auto') {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            itemTheme = prefersDark ? 'dark' : 'light';
        }
        document.documentElement.className = itemTheme === 'dark' ? 'dark' : 'light';
    };

    return {
        switchTheme,
    };
};
