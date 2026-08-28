<template>
    <div>
        <el-drawer
            v-model="drawerVisible"
            :destroy-on-close="true"
            :close-on-click-modal="false"
            :close-on-press-escape="false"
            size="30%"
        >
            <template #header>
                <DrawerHeader :header="$t('setting.proxy')" :back="handleClose" />
            </template>
            <el-form ref="formRef" label-position="top" :model="form" @submit.prevent v-loading="loading">
                <el-row type="flex" justify="center">
                    <el-col :span="22">
                        <el-form-item :label="$t('setting.proxyType')" prop="proxyType">
                            <!-- el-select 把空串视为未选择，故“不启用”用内部值 disable 表示 -->
                            <el-select v-model="form.proxyType" @change="onTypeChange">
                                <el-option key="disable" value="disable" :label="$t('setting.proxyDisable')" />
                                <el-option key="http" value="http" label="HTTP" />
                                <el-option key="https" value="https" label="HTTPS" />
                                <el-option key="socks5" value="socks5" label="SOCKS5" />
                            </el-select>
                        </el-form-item>
                        <template v-if="form.proxyType !== 'disable'">
                            <el-form-item :label="$t('setting.proxyUrl')" prop="proxyUrl" :rules="Rules.requiredInput">
                                <el-input v-model.trim="form.proxyUrl" />
                            </el-form-item>
                            <el-form-item :label="$t('setting.proxyPort')" prop="proxyPort">
                                <el-input v-model.trim="form.proxyPort" :placeholder="$t('setting.proxyOptional')" />
                            </el-form-item>
                            <el-form-item :label="$t('setting.proxyUser')" prop="proxyUser">
                                <el-input
                                    v-model.trim="form.proxyUser"
                                    autocomplete="off"
                                    :placeholder="$t('setting.proxyOptional')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('commons.login.password')" prop="proxyPasswd">
                                <el-input
                                    type="password"
                                    clearable
                                    v-model="form.proxyPasswd"
                                    autocomplete="new-password"
                                    :placeholder="passwordPlaceholder"
                                />
                            </el-form-item>
                            <el-form-item v-if="form.hasStoredPass || form.proxyPasswd" prop="proxyPasswdKeep">
                                <el-checkbox v-model="form.proxyPasswdKeep" true-value="true" false-value="false">
                                    {{ $t('setting.proxyRememberPwd') }}
                                </el-checkbox>
                            </el-form-item>
                            <el-form-item prop="proxyDockerSync">
                                <el-checkbox v-model="form.proxyDockerSync" true-value="true" false-value="false">
                                    {{ $t('setting.proxyDocker') }}
                                </el-checkbox>
                            </el-form-item>
                        </template>
                        <span class="input-help">{{ $t('setting.proxyHelper') }}</span>
                        <span class="input-help">{{ $t('setting.proxyHelper1') }}</span>
                        <span class="input-help">{{ $t('setting.proxyHelper2') }}</span>
                        <span class="input-help">{{ $t('setting.proxyHelper3') }}</span>
                        <span class="input-help">{{ $t('setting.proxyHelper4') }}</span>
                    </el-col>
                </el-row>
            </el-form>
            <template #footer>
                <span class="dialog-footer">
                    <el-button
                        :disabled="form.proxyType === 'disable' || testLoading"
                        :loading="testLoading"
                        @click="onTest"
                    >
                        {{ $t('setting.proxyTest') }}
                    </el-button>
                    <el-button @click="handleClose">{{ $t('commons.button.cancel') }}</el-button>
                    <el-button :disabled="loading" type="primary" @click="onSave(formRef)">
                        {{ $t('commons.button.confirm') }}
                    </el-button>
                </span>
            </template>
        </el-drawer>
    </div>
</template>
<script lang="ts" setup>
import { computed, reactive, ref } from 'vue';
import i18n from '@/lang';
import { MsgError, MsgSuccess } from '@/utils/message';
import { testProxy, updateProxy } from '@/api/modules/setting';
import { Setting } from '@/api/interface/setting';
import { FormInstance } from 'element-plus';
import { ElMessageBox } from 'element-plus';
import { Rules } from '@/global/form-rules';
import DrawerHeader from '@/components/drawer-header/index.vue';

const emit = defineEmits<{ (e: 'search'): void }>();

const drawerVisible = ref();
const loading = ref();
const testLoading = ref();

const form = reactive({
    proxyType: '',
    proxyUrl: '',
    proxyPort: '',
    proxyUser: '',
    proxyPasswd: '',
    proxyPasswdKeep: 'true',
    proxyDockerSync: 'false',
    hasStoredPass: false,
});

const formRef = ref<FormInstance>();

const passwordPlaceholder = computed(() =>
    form.hasStoredPass ? i18n.global.t('setting.proxyPasswdUnchanged') : i18n.global.t('setting.proxyOptional'),
);

const onTypeChange = () => {
    if (form.proxyType === 'disable') {
        form.proxyUrl = '';
        form.proxyPort = '';
        form.proxyUser = '';
        form.proxyPasswd = '';
        form.proxyPasswdKeep = 'true';
        form.hasStoredPass = false;
    }
};

const acceptParams = (params: {
    proxyType: string;
    proxyUrl: string;
    proxyPort: string;
    proxyUser: string;
    proxyPasswdKeep: string;
    proxyDockerSync: string;
}): void => {
    // 后端空串表示未启用，映射为内部值 disable
    form.proxyType = params.proxyType || 'disable';
    form.proxyUrl = params.proxyUrl || '';
    form.proxyPort = params.proxyPort || '';
    form.proxyUser = params.proxyUser || '';
    form.proxyPasswd = '';
    form.hasStoredPass = params.proxyPasswdKeep === 'true';
    form.proxyPasswdKeep = params.proxyPasswdKeep === 'true' ? 'true' : 'false';
    form.proxyDockerSync = params.proxyDockerSync === 'true' ? 'true' : 'false';
    drawerVisible.value = true;
};

const buildReq = (): Setting.ProxyUpdate => ({
    // 内部值 disable 映射回后端的空串语义（不启用）
    proxyType: form.proxyType === 'disable' ? '' : form.proxyType,
    proxyUrl: form.proxyUrl,
    proxyPort: form.proxyPort,
    proxyUser: form.proxyUser,
    // 密码留空且勾选记住时表示沿用已存密码，后端跳过更新；否则 base64 传输新密码
    proxyPasswd:
        form.proxyPasswd === '' && form.hasStoredPass && form.proxyPasswdKeep === 'true'
            ? ''
            : btoa(unescape(encodeURIComponent(form.proxyPasswd))),
    proxyPasswdKeep: form.proxyPasswdKeep,
    proxyDockerSync: form.proxyDockerSync,
});

// confirmDockerSync warns before the save triggers a docker daemon restart:
// containers are briefly stopped (live-restore is off unless enabled in the
// container settings) and the panel needs docker to come back.
const confirmDockerSync = async (): Promise<boolean> => {
    try {
        await ElMessageBox.confirm(
            i18n.global.t('setting.proxyDockerSyncConfirm'),
            i18n.global.t('setting.confDockerProxy'),
            {
                confirmButtonText: i18n.global.t('commons.button.confirm'),
                cancelButtonText: i18n.global.t('commons.button.cancel'),
                type: 'warning',
            },
        );
        return true;
    } catch {
        return false;
    }
};

const onSave = async (formEl: FormInstance | undefined) => {
    if (!formEl) return;
    formEl.validate(async (valid) => {
        if (!valid) return;
        if (form.proxyDockerSync === 'true') {
            const confirmed = await confirmDockerSync();
            if (!confirmed) return;
        }
        loading.value = true;
        await updateProxy(buildReq())
            .then(() => {
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                loading.value = false;
                drawerVisible.value = false;
                emit('search');
            })
            .catch(() => {
                loading.value = false;
            });
    });
};

const onTest = async () => {
    if (form.proxyUrl === '') {
        MsgError(i18n.global.t('setting.proxyAddrRequired'));
        return;
    }
    testLoading.value = true;
    await testProxy(buildReq())
        .then((res) => {
            testLoading.value = false;
            MsgSuccess(i18n.global.t('setting.proxyTestSuccess') + ' ' + res.data);
        })
        .catch(() => {
            testLoading.value = false;
            MsgError(i18n.global.t('setting.proxyTestFailed'));
        });
};

const handleClose = () => {
    drawerVisible.value = false;
};

defineExpose({
    acceptParams,
});
</script>
