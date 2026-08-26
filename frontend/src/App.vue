<template>
    <el-config-provider :locale="i18nLocale" :button="config" size="default">
        <router-view v-if="isRouterAlive" />
    </el-config-provider>
</template>

<script setup lang="ts">
import { reactive, computed, ref, nextTick, provide, watch } from 'vue';
import { GlobalStore } from '@/store';
import zhCn from 'element-plus/es/locale/lang/zh-cn';
import zhTw from 'element-plus/es/locale/lang/zh-tw';
import en from 'element-plus/es/locale/lang/en';
import ja from 'element-plus/es/locale/lang/ja';
import ms from 'element-plus/es/locale/lang/ms';
import ptBR from 'element-plus/es/locale/lang/pt-br';
import ru from 'element-plus/es/locale/lang/ru';
import ko from 'element-plus/es/locale/lang/ko';
import { useTheme } from '@/hooks/use-theme';

const globalStore = GlobalStore();

// 刷新/首次加载时恢复持久化的主题（auto 跟随系统）；此前仅登录页与手动切换会应用，
// 直接刷新任意页面会导致暗色丢失
const { switchTheme } = useTheme();
switchTheme();
// 刷新时恢复面板标题（此前仅登录流程会设置，直接刷新会一直显示 loading...）
document.title = globalStore.themeConfig.panelName || '1Panel';
watch(
    () => globalStore.themeConfig.theme,
    () => switchTheme(),
);
watch(
    () => globalStore.themeConfig.panelName,
    (v) => {
        if (v) document.title = v;
    },
);
const config = reactive({
    autoInsertSpace: false,
});

const i18nLocale = computed(() => {
    if (globalStore.language === 'zh') return zhCn;
    if (globalStore.language === 'tw') return zhTw;
    if (globalStore.language === 'en') return en;
    if (globalStore.language === 'ja') return ja;
    if (globalStore.language === 'ms') return ms;
    if (globalStore.language === 'ru') return ru;
    if (globalStore.language === 'pt-br') return ptBR;
    if (globalStore.language === 'ko') return ko;
    return zhCn;
});

const isRouterAlive = ref(true);

const reload = () => {
    isRouterAlive.value = false;
    nextTick(() => {
        isRouterAlive.value = true;
    });
};
provide('reload', reload);
</script>
