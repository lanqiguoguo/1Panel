/**
 * MFA 登录提交的状态机（从 login-form.vue 的 mfaLogin 抽取，独立可测）。
 *
 * 职责：
 * - 判定自动提交（@input 逐键触发）是否应发出请求：码完整（6 位）且与
 *   上次提交的码不同，避免失败后清空重输相同码时因 lastMfaSubmitted
 *   残留而"改码才能重试"。
 * - 提交失败（业务 406 / 网络或服务异常）后复位 lastMfaSubmitted 并刷新
 *   验证码，保证相同码可立即重试、captcha 保持新鲜。
 * - 406 ErrCaptchaCode（IP 被限流、需要验证码解锁）时通过 onCaptchaRequired
 *   通知组件显示 captcha 输入框；其余 406（ErrAuth，TOTP 错误）保留
 *   errMfaInfo 提示。
 * - 用户重新输入时复位 errMfaInfo 错误提示。
 * - 成功路径回调 onSuccess（登入、跳转等由组件完成）。
 *
 * 组件持有 isLoggingIn / errMfaInfo 等响应式状态，通过 deps 注入（读/写各为
 * 一个函数，保证与组件闭包变量共享同一份状态），本模块不引入 vue 依赖，
 * 便于在 node 下直接测试真实逻辑。
 */

export interface MfaLoginControllerDeps {
    /** 是否正在请求中（login 与 mfaLogin 共用同一把锁），读取当前值 */
    isLoggingIn: () => boolean;
    /** 设置请求中状态 */
    setLoggingIn: (v: boolean) => void;
    /** 重新输入时复位 MFA 错误提示 */
    setErrMfaInfo: (v: boolean) => void;
    /** 提交失败（406/异常）后刷新验证码 */
    refreshCaptcha: () => void;
    /** 提交失败且确需兜底提示（纯网络断连，拦截器未提示过）时调用 */
    notifyMfaError: () => void;
    /** 406 ErrCaptchaCode：IP 被限流，需显示 captcha 输入框并刷新验证码 */
    onCaptchaRequired: () => void;
    /** 提交请求，返回业务码与消息（拦截器已按业务码过滤，此处直接拿 envelope） */
    submit: (code: string) => Promise<MfaSubmitResult>;
    /** 成功路径：登入状态、跳转等 */
    onSuccess: () => void;
}

export interface MfaLoginController {
    /** 自动提交（@input 逐键触发），返回是否真的发出了请求 */
    onInput: (code: string) => boolean;
    /** 手动提交（点击"验证"按钮），返回是否真的发出了请求 */
    onSubmit: (code: string) => Promise<boolean>;
}

/** 业务码约定：406 = 认证失败（ErrAuth / ErrCaptchaCode），200 = 成功 */
const CODE_AUTH = 406;
const CODE_SUCCESS = 200;

/** 后端 406 的 message：ErrCaptchaCode = IP 被限流需验证码解锁；ErrAuth = TOTP 错误 */
const MSG_CAPTCHA_REQUIRED = 'ErrCaptchaCode';

/**
 * 是否需要兜底错误 toast。axios 拦截器（api/index.ts）已覆盖：
 * - 超时（message 含 timeout）→ 已提示
 * - 5xx（error.response 存在）→ checkStatus 已提示
 * - HTTP 200 + 业务错误码 → 成功分支已 MsgError 并 reject 原始 data（非 AxiosError）
 * 仅"纯网络断连"（AxiosError 且无 response）时拦截器无提示，需要兜底。
 */
export function shouldNotifyMfaError(error: unknown): boolean {
    if (!error || typeof error !== 'object') {
        return false;
    }
    const e = error as { isAxiosError?: boolean; response?: unknown; message?: string };
    return e.isAxiosError === true && !e.response && !(e.message || '').includes('timeout');
}

export interface MfaSubmitResult {
    /** 业务码（200 成功 / 406 认证失败） */
    code: number;
    /** 406 时的业务消息（'ErrCaptchaCode' | 'ErrAuth' 等） */
    message: string;
}

export function createMfaLoginController(deps: MfaLoginControllerDeps): MfaLoginController {
    let lastMfaSubmitted = '';

    /** 提交失败后的公共复位：允许相同码重试 + 刷新验证码 */
    const resetAfterFailure = () => {
        lastMfaSubmitted = '';
        deps.refreshCaptcha();
    };

    const doSubmit = async (code: string): Promise<void> => {
        lastMfaSubmitted = code;
        deps.setLoggingIn(true);
        try {
            const { code: bizCode, message } = await deps.submit(code);
            if (bizCode === CODE_AUTH) {
                if (message === MSG_CAPTCHA_REQUIRED) {
                    // IP 被限流：验证码是解锁机制。清空输入、显示 captcha 输入框
                    // 并刷新验证码，让用户填码后重新提交（TOTP 与 captcha 一起）。
                    deps.onCaptchaRequired();
                } else {
                    // TOTP 错误：保留错误提示，但允许相同码重试并刷新验证码
                    deps.setErrMfaInfo(true);
                }
                resetAfterFailure();
                return;
            }
            if (bizCode !== CODE_SUCCESS) {
                // 拦截器对非 200/406 业务码已弹 MsgError，这里只复位状态
                resetAfterFailure();
                return;
            }
            deps.onSuccess();
        } catch (error) {
            // 网络断连/超时/5xx：拦截器（api/index.ts）对超时与 5xx 已提示，
            // 仅纯网络断连（AxiosError 且无 response、非超时）时兜底 toast，
            // 避免与拦截器重复提示。状态无论如何必须复位。
            resetAfterFailure();
            if (shouldNotifyMfaError(error)) {
                deps.notifyMfaError();
            }
        } finally {
            deps.setLoggingIn(false);
        }
    };

    const onInput = (code: string): boolean => {
        if (deps.isLoggingIn()) return false;
        // 用户开始重新输入（清空后重输），先复位上次的错误提示
        deps.setErrMfaInfo(false);
        if (code.length !== 6 || code === lastMfaSubmitted) {
            return false;
        }
        // 不在调用方 await：@input 逐键触发，避免快速输入期间请求堆积
        void doSubmit(code);
        return true;
    };

    const onSubmit = async (code: string): Promise<boolean> => {
        if (deps.isLoggingIn()) return false;
        deps.setErrMfaInfo(false);
        if (!code) {
            return false;
        }
        await doSubmit(code);
        return true;
    };

    return { onInput, onSubmit };
}
