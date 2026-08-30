<template>
    <div>
        <el-drawer
            v-model="drawerVisible"
            :destroy-on-close="true"
            :close-on-click-modal="false"
            :close-on-press-escape="false"
            size="50%"
        >
            <template #header>
                <DrawerHeader :header="title + $t('setting.backupAccount')" :back="handleClose" />
            </template>
            <el-form @submit.prevent ref="formRef" v-loading="loading" label-position="top" :model="sftpData.rowData">
                <el-row type="flex" justify="center">
                    <el-col :span="22">
                        <el-form-item :label="$t('commons.table.type')" prop="type" :rules="Rules.requiredSelect">
                            <el-tag>{{ $t('setting.' + sftpData.rowData!.type) }}</el-tag>
                        </el-form-item>
                        <el-form-item :label="$t('setting.address')" prop="varsJson.address" :rules="Rules.host">
                            <el-input v-model.trim="sftpData.rowData!.varsJson['address']" />
                        </el-form-item>
                        <el-form-item :label="$t('commons.table.port')" prop="varsJson.port" :rules="[Rules.port]">
                            <el-input-number
                                :min="0"
                                :max="65535"
                                v-model.number="sftpData.rowData!.varsJson['port']"
                            />
                        </el-form-item>
                        <el-form-item
                            :label="$t('commons.login.username')"
                            prop="accessKey"
                            :rules="[Rules.requiredInput]"
                        >
                            <el-input v-model.trim="sftpData.rowData!.accessKey" />
                        </el-form-item>
                        <el-form-item :label="$t('commons.login.password')" prop="credential" :rules="credentialRule">
                            <el-input
                                type="password"
                                clearable
                                show-password
                                v-model.trim="sftpData.rowData!.credential"
                                :placeholder="credentialPlaceholder"
                            />
                            <el-checkbox
                                v-if="isEdit && hasStoredCredential"
                                v-model="keepCredential"
                                style="margin-top: 5px"
                            >
                                {{ $t('setting.keepCredential') }}
                            </el-checkbox>
                        </el-form-item>
                        <el-form-item :label="$t('setting.backupDir')" prop="bucket" :rules="[Rules.requiredInput]">
                            <el-input v-model.trim="sftpData.rowData!.bucket" />
                        </el-form-item>
                    </el-col>
                </el-row>
            </el-form>
            <template #footer>
                <span class="dialog-footer">
                    <el-button :disabled="loading" @click="handleClose">
                        {{ $t('commons.button.cancel') }}
                    </el-button>
                    <el-button :disabled="loading" type="primary" @click="onSubmit(formRef)">
                        {{ $t('commons.button.confirm') }}
                    </el-button>
                </span>
            </template>
        </el-drawer>
    </div>
</template>

<script lang="ts" setup>
import { computed, ref } from 'vue';
import { Rules } from '@/global/form-rules';
import i18n from '@/lang';
import { ElForm } from 'element-plus';
import { Backup } from '@/api/interface/backup';
import DrawerHeader from '@/components/drawer-header/index.vue';
import { addBackup, editBackup } from '@/api/modules/setting';
import { MsgSuccess } from '@/utils/message';
import { FormItemRule } from 'element-plus';

const loading = ref(false);
type FormInstance = InstanceType<typeof ElForm>;
const formRef = ref<FormInstance>();

const emit = defineEmits(['search']);

interface DialogProps {
    title: string;
    rowData?: Backup.BackupInfo;
    getTableList?: () => Promise<any>;
}
const title = ref<string>('');
const drawerVisible = ref(false);
const sftpData = ref<DialogProps>({
    title: '',
});

// 编辑态凭据 keep 语义：回显脱敏后，凭据字段留空（默认勾选“沿用原密码”）
// 表示保留已存凭据；取消勾选后留空则清空凭据。
const isEdit = ref(false);
const hasStoredCredential = ref(false);
const keepCredential = ref(true);

const credentialPlaceholder = computed(() =>
    isEdit.value && hasStoredCredential.value && keepCredential.value
        ? i18n.global.t('setting.keepCredentialPlaceholder')
        : '',
);
const credentialRule = computed<FormItemRule[]>(() => {
    // 新建时必须填写；编辑时保留原凭据（keep）时允许为空
    if (isEdit.value && hasStoredCredential.value && keepCredential.value) {
        return [];
    }
    return [Rules.requiredInput];
});

const acceptParams = (params: DialogProps): void => {
    sftpData.value = params;
    if (sftpData.value.title === 'create') {
        sftpData.value.rowData.varsJson['port'] = 22;
        isEdit.value = false;
        hasStoredCredential.value = false;
        keepCredential.value = false;
    } else {
        // 编辑态：后端不回显凭据明文，表单留空并默认 keep 原值
        isEdit.value = true;
        hasStoredCredential.value = !!sftpData.value.rowData.id;
        keepCredential.value = true;
        sftpData.value.rowData.credential = '';
    }
    title.value = i18n.global.t('commons.button.' + sftpData.value.title);
    drawerVisible.value = true;
};

const handleClose = () => {
    emit('search');
    drawerVisible.value = false;
};

const onSubmit = async (formEl: FormInstance | undefined) => {
    if (!formEl) return;
    formEl.validate(async (valid) => {
        if (!valid) return;
        if (!sftpData.value.rowData) return;
        // keep 语义：凭据字段留空时后端自动保留原值，填写则替换
        sftpData.value.rowData.vars = JSON.stringify(sftpData.value.rowData!.varsJson);
        loading.value = true;
        if (sftpData.value.title === 'create') {
            await addBackup(sftpData.value.rowData)
                .then(() => {
                    loading.value = false;
                    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                    emit('search');
                    drawerVisible.value = false;
                })
                .catch(() => {
                    loading.value = false;
                });
            return;
        }
        await editBackup(sftpData.value.rowData)
            .then(() => {
                loading.value = false;
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                emit('search');
                drawerVisible.value = false;
            })
            .catch(() => {
                loading.value = false;
            });
    });
};

defineExpose({
    acceptParams,
});
</script>
