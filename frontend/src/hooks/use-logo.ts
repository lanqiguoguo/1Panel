import { GlobalStore } from '@/store';

export const useLogo = async () => {
    const globalStore = GlobalStore();
    const link = (document.querySelector("link[rel*='icon']") || document.createElement('link')) as HTMLLinkElement;
    link.type = 'image/x-icon';
    link.rel = 'shortcut icon';
    link.href = globalStore.themeConfig.favicon ? `/api/v1/images/favicon?t=${Date.now()}` : '/public/favicon.png';
    document.getElementsByTagName('head')[0].appendChild(link);
};
