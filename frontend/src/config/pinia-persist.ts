import { PersistedStateOptions } from 'pinia-plugin-persistedstate';

/**
 * @description pinia持久化参数配置
 * @param {String} key 存储到持久化的 name
 * @param {Array<string>} [paths] 可选的持久化字段白名单（支持 dot-notation），
 *                                传入后仅这些键会被写入 storage，会话敏感键不再落盘
 * @return persist
 * */
const piniaPersistConfig = (key: string, paths?: Array<string>) => {
    const persist: PersistedStateOptions = {
        key,
        storage: window.localStorage,
        // storage: window.sessionStorage,
    };
    if (paths && paths.length > 0) {
        persist.paths = paths;
    }
    return persist;
};

export default piniaPersistConfig;
