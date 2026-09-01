<template>
    <div v-loading="loading">
        <el-drawer
            v-model="passwordVisible"
            :destroy-on-close="true"
            :close-on-click-modal="false"
            :close-on-press-escape="false"
            size="30%"
        >
            <template #header>
                <DrawerHeader :header="$t('setting.changePassword')" :back="handleClose" />
            </template>
            <el-form ref="passFormRef" label-position="top" :model="passForm" :rules="passRules">
                <el-row type="flex" justify="center">
                    <el-col :span="22">
                        <el-form-item :label="$t('setting.oldPassword')" prop="oldPassword">
                            <el-input type="password" show-password clearable v-model.trim="passForm.oldPassword" />
                        </el-form-item>
                        <el-form-item
                            v-if="complexityVerification === 'disable'"
                            :label="$t('setting.newPassword')"
                            prop="newPassword"
                        >
                            <el-input type="password" show-password clearable v-model.trim="passForm.newPassword" />
                        </el-form-item>
                        <el-form-item
                            v-if="complexityVerification === 'enable'"
                            :label="$t('setting.newPassword')"
                            prop="newPasswordComplexity"
                        >
                            <el-input
                                type="password"
                                show-password
                                clearable
                                v-model.trim="passForm.newPasswordComplexity"
                            />
                        </el-form-item>
                        <el-form-item :label="$t('setting.retryPassword')" prop="retryPassword">
                            <el-input type="password" show-password clearable v-model.trim="passForm.retryPassword" />
                        </el-form-item>
                    </el-col>
                </el-row>
            </el-form>
            <template #footer>
                <span class="dialog-footer">
                    <el-button :disabled="loading" @click="passwordVisible = false">
                        {{ $t('commons.button.cancel') }}
                    </el-button>
                    <el-button :disabled="loading" type="primary" @click="submitChangePassword(passFormRef)">
                        {{ $t('commons.button.confirm') }}
                    </el-button>
                </span>
            </template>
        </el-drawer>
    </div>
</template>

<script lang="ts" setup>
import { Rules } from '@/global/form-rules';
import i18n from '@/lang';
import router, { clearSessionCache } from '@/routers';
import { MsgError, MsgSuccess } from '@/utils/message';
import { FormInstance } from 'element-plus';
import { GlobalStore, TabsStore } from '@/store';
import { reactive, ref } from 'vue';
import { updatePassword } from '@/api/modules/setting';
import DrawerHeader from '@/components/drawer-header/index.vue';
import { logOutApi } from '@/api/modules/auth';
import { encryptPassword } from '@/utils/util';

const globalStore = GlobalStore();
const passFormRef = ref<FormInstance>();
const passRules = reactive({
    oldPassword: [Rules.requiredInput, Rules.noSpace],
    newPassword: [Rules.requiredInput, Rules.noSpace],
    newPasswordComplexity: [Rules.requiredInput, Rules.noSpace, Rules.password],
    retryPassword: [Rules.requiredInput, Rules.noSpace, { validator: checkPassword, trigger: 'blur' }],
});

const loading = ref(false);
const passwordVisible = ref<boolean>(false);
const passForm = reactive({
    oldPassword: '',
    newPassword: '',
    newPasswordComplexity: '',
    retryPassword: '',
});
const complexityVerification = ref();

interface DialogProps {
    complexityVerification: string;
}
const acceptParams = (params: DialogProps): void => {
    complexityVerification.value = params.complexityVerification;
    passForm.oldPassword = '';
    passForm.newPassword = '';
    passForm.newPasswordComplexity = '';
    passForm.retryPassword = '';
    passwordVisible.value = true;
};

function checkPassword(rule: any, value: any, callback: any) {
    let password = complexityVerification.value === 'disable' ? passForm.newPassword : passForm.newPasswordComplexity;
    if (password !== passForm.retryPassword) {
        return callback(new Error(i18n.global.t('commons.rule.rePassword')));
    }
    callback();
}

const submitChangePassword = async (formEl: FormInstance | undefined) => {
    if (!formEl) return;
    formEl.validate(async (valid) => {
        if (!valid) return;
        let password =
            complexityVerification.value === 'disable' ? passForm.newPassword : passForm.newPasswordComplexity;
        if (password === passForm.oldPassword) {
            MsgError(i18n.global.t('setting.duplicatePassword'));
            return;
        }
        // passwords must never travel in plaintext: wrap them with the same
        // RSA/AES envelope the login form uses
        const oldEncrypted = encryptPassword(passForm.oldPassword);
        const newEncrypted = encryptPassword(password);
        if (!oldEncrypted || !newEncrypted) {
            MsgError(i18n.global.t('commons.login.encryptErr'));
            return;
        }
        loading.value = true;
        await updatePassword({ oldPassword: oldEncrypted, newPassword: newEncrypted })
            .then(async () => {
                loading.value = false;
                passwordVisible.value = false;
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                await logOutApi();
                clearSessionCache();
                TabsStore().removeAllTabs();
                router.push({ name: 'entrance', params: { code: globalStore.entrance } });
                // 登出后清空内存中的安全入口码（entrance 已不再持久化到 localStorage）；
                // 需在上方 push 之后执行，避免跳转 URL 丢失入口码
                globalStore.entrance = '';
                globalStore.setLogStatus(false);
            })
            .catch(() => {
                loading.value = false;
            });
    });
};
const handleClose = () => {
    passwordVisible.value = false;
};

defineExpose({
    acceptParams,
});
</script>
