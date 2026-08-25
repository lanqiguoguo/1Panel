<template>
    <div v-loading="loading">
        <LayoutContent :title="$t('setting.panel')" :divider="true">
            <template #main>
                <el-form
                    :model="form"
                    :label-position="mobile ? 'top' : 'left'"
                    label-width="auto"
                    class="sm:w-full md:w-4/5 lg:w-3/5 2xl:w-1/2 max-w-max ml-8"
                >
                    <el-form-item :label="$t('setting.user')" prop="userName">
                        <el-input disabled v-model="form.userName">
                            <template #append>
                                <el-button @click="onChangeUserName()" icon="Setting">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                    </el-form-item>

                    <el-form-item :label="$t('setting.passwd')" prop="password">
                        <el-input type="password" disabled v-model="form.password">
                            <template #append>
                                <el-button icon="Setting" @click="onChangePassword">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                    </el-form-item>

                    <el-form-item :label="$t('setting.theme')" prop="theme">
                        <div class="flex justify-center items-center sm:gap-6 gap-2">
                            <div class="sm:contents hidden">
                                <el-radio-group @change="onSave('Theme', form.theme)" v-model="form.theme">
                                    <el-radio-button value="light">
                                        <span>{{ $t('setting.light') }}</span>
                                    </el-radio-button>
                                    <el-radio-button value="dark">
                                        <span>{{ $t('setting.dark') }}</span>
                                    </el-radio-button>
                                    <el-radio-button value="auto">
                                        <span>{{ $t('setting.auto') }}</span>
                                    </el-radio-button>
                                </el-radio-group>
                            </div>
                            <div class="sm:hidden block w-32 !h-[33.5px]">
                                <el-select @change="onSave('Theme', form.theme)" v-model="form.theme">
                                    <el-option key="light" value="light" :label="$t('setting.light')">
                                        {{ $t('setting.light') }}
                                    </el-option>
                                    <el-option key="dark" value="dark" :label="$t('setting.dark')">
                                        {{ $t('setting.dark') }}
                                    </el-option>
                                    <el-option key="auto" value="auto" :label="$t('setting.auto')">
                                        {{ $t('setting.auto') }}
                                    </el-option>
                                </el-select>
                            </div>
                        </div>
                    </el-form-item>

                    <el-form-item :label="$t('setting.menuTabs')" prop="menuTabs">
                        <el-radio-group @change="onSave('MenuTabs', form.menuTabs)" v-model="form.menuTabs">
                            <el-radio-button value="enable">
                                <span>{{ $t('commons.button.enable') }}</span>
                            </el-radio-button>
                            <el-radio-button value="disable">
                                <span>{{ $t('commons.button.disable') }}</span>
                            </el-radio-button>
                        </el-radio-group>
                    </el-form-item>

                    <el-form-item :label="$t('setting.title')" prop="panelName">
                        <el-input disabled v-model="form.panelName">
                            <template #append>
                                <el-button icon="Setting" @click="onChangeTitle">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                    </el-form-item>

                    <el-form-item :label="$t('setting.language')" prop="language">
                        <el-select
                            class="sm:!w-1/2 !w-full"
                            @change="onSave('Language', form.language)"
                            v-model="form.language"
                        >
                            <el-option
                                v-for="option in languageOptions"
                                :key="option.value"
                                :value="option.value"
                                :label="option.label"
                            >
                                {{ option.label }}
                            </el-option>
                        </el-select>
                    </el-form-item>

                    <el-form-item :label="$t('setting.sessionTimeout')" prop="sessionTimeout">
                        <el-input disabled v-model.number="form.sessionTimeout">
                            <template #append>
                                <el-button @click="onChangeTimeout" icon="Setting">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                        <span class="input-help">
                            {{ $t('setting.sessionTimeoutHelper', [form.sessionTimeout]) }}
                        </span>
                    </el-form-item>

                    <el-form-item :label="$t('setting.defaultNetwork')">
                        <el-input disabled v-model="form.defaultNetworkVal">
                            <template #append>
                                <el-button v-show="!show" @click="onChangeNetwork" icon="Setting">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                    </el-form-item>

                    <el-form-item :label="$t('setting.systemIP')" prop="systemIP">
                        <el-input disabled v-if="form.systemIP" v-model="form.systemIP">
                            <template #append>
                                <el-button @click="onChangeSystemIP" icon="Setting">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                        <el-input disabled v-if="!form.systemIP" v-model="unset">
                            <template #append>
                                <el-button @click="onChangeSystemIP" icon="Setting">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-input>
                    </el-form-item>

                    <el-form-item :label="$t('setting.apiInterface')" prop="apiInterface">
                        <el-switch
                            @change="onChangeApiInterfaceStatus"
                            v-model="form.apiInterfaceStatus"
                            active-value="enable"
                            inactive-value="disable"
                        />
                        <span class="input-help">{{ $t('setting.apiInterfaceHelper') }}</span>
                        <div v-if="form.apiInterfaceStatus === 'enable'">
                            <div>
                                <el-button link type="primary" @click="onChangeApiInterfaceStatus">
                                    {{ $t('commons.button.view') }}
                                </el-button>
                            </div>
                        </div>
                    </el-form-item>

                    <el-form-item :label="$t('setting.developerMode')" prop="developerMode">
                        <el-radio-group
                            @change="onSave('DeveloperMode', form.developerMode)"
                            v-model="form.developerMode"
                        >
                            <el-radio-button value="enable">
                                <span>{{ $t('commons.button.enable') }}</span>
                            </el-radio-button>
                            <el-radio-button value="disable">
                                <span>{{ $t('commons.button.disable') }}</span>
                            </el-radio-button>
                        </el-radio-group>
                        <span class="input-help">{{ $t('setting.developerModeHelper') }}</span>
                    </el-form-item>
                </el-form>
            </template>
        </LayoutContent>

        <Password ref="passwordRef" />
        <UserName ref="userNameRef" />
        <PanelName ref="panelNameRef" @search="search()" />
        <SystemIP ref="systemIPRef" @search="search()" />
        <ApiInterface ref="apiInterfaceRef" @search="search()" />
        <Timeout ref="timeoutRef" @search="search()" />
        <Network ref="networkRef" @search="search()" />
    </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, computed } from 'vue';
import { ElForm, ElMessageBox } from 'element-plus';
import { getSettingInfo, updateSetting, getSystemAvailable, updateApiConfig } from '@/api/modules/setting';
import { GlobalStore } from '@/store';
import { useI18n } from 'vue-i18n';
import { useTheme } from '@/hooks/use-theme';
import { MsgSuccess } from '@/utils/message';
import Password from '@/views/setting/panel/password/index.vue';
import UserName from '@/views/setting/panel/username/index.vue';
import Timeout from '@/views/setting/panel/timeout/index.vue';
import PanelName from '@/views/setting/panel/name/index.vue';
import SystemIP from '@/views/setting/panel/systemip/index.vue';
import Network from '@/views/setting/panel/default-network/index.vue';
import ApiInterface from '@/views/setting/panel/api-interface/index.vue';

const loading = ref(false);
const i18n = useI18n();
const globalStore = GlobalStore();

const { switchTheme } = useTheme();

const mobile = computed(() => {
    return globalStore.isMobile();
});

const form = reactive({
    userName: '',
    password: '',
    email: '',
    sessionTimeout: 0,
    localTime: '',
    timeZone: '',
    ntpSite: '',
    panelName: '',
    systemIP: '',
    theme: '',
    menuTabs: '',
    language: '',
    complexityVerification: '',
    defaultNetwork: '',
    defaultNetworkVal: '',
    developerMode: '',

    apiInterfaceStatus: 'disable',
    apiKey: '',
    ipWhiteList: '',
    apiKeyValidityTime: 120,
});

const show = ref();

const userNameRef = ref();
const passwordRef = ref();
const panelNameRef = ref();
const systemIPRef = ref();
const timeoutRef = ref();
const networkRef = ref();
const apiInterfaceRef = ref();
const unset = ref(i18n.t('setting.unSetting'));

const languageOptions = ref([
    { value: 'zh', label: '中文(简体)' },
    { value: 'tw', label: '中文(繁體)' },
    ...(!globalStore.isIntl ? [{ value: 'en', label: 'English' }] : []),
    { value: 'ja', label: '日本語' },
    { value: 'pt-BR', label: 'Português (Brasil)' },
    { value: 'ko', label: '한국어' },
    { value: 'ru', label: 'Русский' },
    { value: 'ms', label: 'Bahasa Melayu' },
]);

if (globalStore.isIntl) {
    languageOptions.value.unshift({ value: 'en', label: 'English' });
}

const search = async () => {
    const res = await getSettingInfo();
    form.userName = res.data.userName;
    form.password = '******';
    form.sessionTimeout = Number(res.data.sessionTimeout);
    form.localTime = res.data.localTime;
    form.timeZone = res.data.timeZone;
    form.ntpSite = res.data.ntpSite;
    form.panelName = res.data.panelName;
    form.systemIP = res.data.systemIP;
    form.menuTabs = res.data.menuTabs;
    form.language = res.data.language;
    form.complexityVerification = res.data.complexityVerification;
    form.defaultNetwork = res.data.defaultNetwork;
    form.defaultNetworkVal = res.data.defaultNetwork === 'all' ? i18n.t('commons.table.all') : res.data.defaultNetwork;
    form.developerMode = res.data.developerMode;

    form.apiInterfaceStatus = res.data.apiInterfaceStatus;
    form.apiKey = res.data.apiKey;
    form.ipWhiteList = res.data.ipWhiteList;
    form.apiKeyValidityTime = res.data.apiKeyValidityTime;

    form.theme = globalStore.themeConfig.theme || res.data.theme || 'light';
};

const onChangePassword = () => {
    passwordRef.value.acceptParams({ complexityVerification: form.complexityVerification });
};
const onChangeUserName = () => {
    userNameRef.value.acceptParams({ userName: form.userName });
};
const onChangeTitle = () => {
    panelNameRef.value.acceptParams({ panelName: form.panelName });
};
const onChangeTimeout = () => {
    timeoutRef.value.acceptParams({ sessionTimeout: form.sessionTimeout });
};
const onChangeSystemIP = () => {
    systemIPRef.value.acceptParams({ systemIP: form.systemIP });
};
const onChangeApiInterfaceStatus = async () => {
    if (form.apiInterfaceStatus === 'enable') {
        apiInterfaceRef.value.acceptParams({
            apiInterfaceStatus: form.apiInterfaceStatus,
            apiKey: form.apiKey,
            ipWhiteList: form.ipWhiteList,
            apiKeyValidityTime: form.apiKeyValidityTime,
        });
        return;
    }
    ElMessageBox.confirm(i18n.t('setting.apiInterfaceClose'), i18n.t('setting.apiInterface'), {
        confirmButtonText: i18n.t('commons.button.confirm'),
        cancelButtonText: i18n.t('commons.button.cancel'),
    })
        .then(async () => {
            loading.value = true;
            form.apiInterfaceStatus = 'disable';
            let param = {
                apiKey: form.apiKey,
                ipWhiteList: form.ipWhiteList,
                apiInterfaceStatus: form.apiInterfaceStatus,
                apiKeyValidityTime: form.apiKeyValidityTime,
            };
            await updateApiConfig(param)
                .then(() => {
                    loading.value = false;
                    search();
                    MsgSuccess(i18n.t('commons.msg.operationSuccess'));
                })
                .catch(() => {
                    loading.value = false;
                });
        })
        .catch(() => {
            form.apiInterfaceStatus = 'enable';
        });
};
const onChangeNetwork = () => {
    networkRef.value.acceptParams({ defaultNetwork: form.defaultNetwork });
};

const handleThemeChange = async (val: string) => {
    globalStore.themeConfig.theme = val;
    switchTheme();
};

const onSave = async (key: string, val: any) => {
    loading.value = true;
    let param = {
        key: key,
        value: val + '',
    };
    try {
        await updateSetting(param);
        if (key === 'Language') {
            i18n.locale.value = val;
            globalStore.updateLanguage(val);
            location.reload();
        }

        if (key === 'Theme') {
            await handleThemeChange(val);
        }
        if (key === 'MenuTabs') {
            globalStore.setOpenMenuTabs(val === 'enable');
        }
        MsgSuccess(i18n.t('commons.msg.operationSuccess'));
        await search();
    } catch (error) {
    } finally {
        loading.value = false;
    }
};

onMounted(() => {
    search();
    getSystemAvailable();
});
</script>

<style scoped lang="scss">
:deep(.el-radio-group) {
    min-width: max-content;
}
</style>
