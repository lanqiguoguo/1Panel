import axios, { AxiosInstance, AxiosError, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { ResultData } from '@/api/interface';
import { ResultEnum } from '@/enums/http-enum';
import { checkStatus } from './helper/check-status';
import router from '@/routers';
import { GlobalStore } from '@/store';
import { MsgError } from '@/utils/message';
import { Base64 } from 'js-base64';
import i18n from '@/lang';

const globalStore = GlobalStore();

const config = {
    baseURL: import.meta.env.VITE_API_URL as string,
    timeout: ResultEnum.TIMEOUT as number,
    withCredentials: true,
};

class RequestHttp {
    service: AxiosInstance;
    public constructor(config: AxiosRequestConfig) {
        this.service = axios.create(config);
        this.service.interceptors.request.use(
            (config: AxiosRequestConfig) => {
                let language = globalStore.language === 'tw' ? 'zh-Hant' : globalStore.language;
                config.headers = {
                    'Accept-Language': language,
                    ...config.headers,
                };
                if (config.url === '/auth/login' || config.url === '/auth/mfalogin') {
                    let entrance = Base64.encode(globalStore.entrance);
                    config.headers.EntranceCode = entrance;
                }
                return {
                    ...config,
                } as InternalAxiosRequestConfig<any>;
            },
            (error: AxiosError) => {
                return Promise.reject(error);
            },
        );

        this.service.interceptors.response.use(
            (response: AxiosResponse) => {
                globalStore.errStatus = '';
                const { data } = response;
                if (data.code == ResultEnum.OVERDUE || data.code == ResultEnum.FORBIDDEN) {
                    globalStore.setLogStatus(false);
                    router.push({
                        name: 'entrance',
                        params: { code: globalStore.entrance },
                    });
                    return Promise.reject(data);
                }
                if (data.code == ResultEnum.NOTFOUND) {
                    globalStore.errStatus = 'err-found';
                    return;
                }
                if (data.code == ResultEnum.ERRIP) {
                    globalStore.errStatus = 'err-ip';
                    return;
                }
                if (data.code == ResultEnum.ERRDOMAIN) {
                    globalStore.errStatus = 'err-domain';
                    return;
                }
                if (data.code == ResultEnum.UNSAFETY) {
                    globalStore.errStatus = 'err-unsafe';
                    return;
                }
                if (data.code == ResultEnum.EXPIRED) {
                    router.push({ name: 'Expired' });
                    return;
                }
                if (data.code == ResultEnum.ERRGLOBALLOADDING) {
                    globalStore.setGlobalLoading(true);
                    globalStore.setLoadingText(data.message);
                    // 407 由后端 GlobalLoading 中间件在系统升级/快照恢复等耗时操作期间返回，
                    // 操作完成（成功或失败）后端都会把 SystemStatus 复位为 Free。不能依赖
                    // "后续成功响应"清除（期间所有请求都被 407 拦截，且操作可能远超 30s），
                    // 改为轮询 /settings/search：状态回到 Free 即清除，时长与操作实际耗时一致。
                    // 轮询请求本身在操作期间也会被 407 拦截（服务活着、操作进行中），此时
                    // 继续轮询；只有连接失败/超时/5xx（服务可能崩溃）才累计失败次数，
                    // 连续失败达到上限（6 次 × 30s = 3 分钟）即停止轮询并提示，
                    // 避免后端崩溃后 loading 无限转圈。
                    if (!globalStore.globalLoadingTimer) {
                        let failCount = 0;
                        const timer = setInterval(async () => {
                            let res: any;
                            try {
                                res = await http.post<any>(`/settings/search`);
                            } catch {
                                // 连接失败/超时/5xx（服务可能崩溃）才累计失败次数，
                                // 连续达到上限（6 次 × 30s = 3 分钟）即停止轮询并提示。
                                failCount++;
                                if (failCount >= 6) {
                                    clearInterval(timer);
                                    globalStore.globalLoadingTimer = null;
                                    globalStore.setGlobalLoading(false);
                                    MsgError(i18n.global.t('commons.msg.systemOpLost'));
                                }
                                return;
                            }
                            // 能拿到应答说明服务活着。操作期间轮询请求被 407 拦截时，
                            // 拦截器返回 undefined——这是"仍在升级/恢复中"的正常状态，
                            // 不计失败，继续轮询；只有 systemStatus 回到 Free 才清除。
                            failCount = 0;
                            if (res?.data?.systemStatus === 'Free') {
                                clearInterval(timer);
                                globalStore.globalLoadingTimer = null;
                                globalStore.setGlobalLoading(false);
                            }
                        }, 30000);
                        globalStore.globalLoadingTimer = timer;
                    }
                    return;
                } else {
                    if (globalStore.isLoading) {
                        globalStore.setGlobalLoading(false);
                    }
                }
                if (data.code == ResultEnum.ERRAUTH) {
                    return data;
                }
                if (data.code && data.code !== ResultEnum.SUCCESS) {
                    MsgError(data.message);
                    return Promise.reject(data);
                }
                return data;
            },
            async (error: AxiosError) => {
                globalStore.errStatus = '';
                const { response } = error;
                if (error.message.indexOf('timeout') !== -1) MsgError('请求超时！请您稍后重试');
                if (response) {
                    switch (response.status) {
                        case 310:
                            globalStore.errStatus = 'err-ip';
                            router.push({
                                name: 'entrance',
                                params: { code: globalStore.entrance },
                            });
                            return;
                        case 311:
                            globalStore.errStatus = 'err-domain';
                            router.push({
                                name: 'entrance',
                                params: { code: globalStore.entrance },
                            });
                            return;
                        case 312:
                            globalStore.errStatus = 'err-entrance';
                            router.push({
                                name: 'entrance',
                                params: { code: globalStore.entrance },
                            });
                            return;
                        case 313:
                            router.push({ name: 'Expired' });
                            return;
                        case 500:
                        case 407:
                            checkStatus(
                                response.status,
                                response.data && response.data['message'] ? response.data['message'] : '',
                            );
                            return Promise.reject(error);
                        default:
                            globalStore.isLogin = false;
                            globalStore.errStatus = 'code-' + response.status;
                            router.push({
                                name: 'entrance',
                                params: { code: globalStore.entrance },
                            });
                            return Promise.reject(error);
                    }
                }
                if (!window.navigator.onLine) router.replace({ path: '/500' });
                return Promise.reject(error);
            },
        );
    }

    get<T>(url: string, params?: object, _object = {}): Promise<ResultData<T>> {
        return this.service.get(url, { params, ..._object });
    }
    post<T>(url: string, params?: object, timeout?: number): Promise<ResultData<T>> {
        return this.service.post(url, params, {
            baseURL: import.meta.env.VITE_API_URL as string,
            timeout: timeout ? timeout : (ResultEnum.TIMEOUT as number),
            withCredentials: true,
        });
    }
    put<T>(url: string, params?: object, _object = {}): Promise<ResultData<T>> {
        return this.service.put(url, params, _object);
    }
    delete<T>(url: string, params?: any, _object = {}): Promise<ResultData<T>> {
        return this.service.delete(url, { params, ..._object });
    }
    download<BlobPart>(url: string, params?: object, _object = {}): Promise<BlobPart> {
        return this.service.post(url, params, _object);
    }
    upload<T>(url: string, params: object = {}, config?: AxiosRequestConfig): Promise<T> {
        return this.service.post(url, params, config);
    }
}

export default new RequestHttp(config);
