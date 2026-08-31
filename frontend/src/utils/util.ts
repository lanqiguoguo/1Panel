import { AcmeAccountTypes, DNSTypes, KeyTypes } from '@/global/mimetype';
import i18n from '@/lang';
import useClipboard from 'vue-clipboard3';
const { toClipboard } = useClipboard();
import { MsgError, MsgSuccess } from '@/utils/message';
import JSEncrypt from 'jsencrypt';
import CryptoJS from 'crypto-js';

export function deepCopy<T>(obj: any): T {
    let newObj: any;
    try {
        newObj = obj.push ? [] : {};
    } catch (error) {
        newObj = {};
    }
    for (let attr in obj) {
        if (typeof obj[attr] === 'object') {
            newObj[attr] = deepCopy(obj[attr]);
        } else {
            newObj[attr] = obj[attr];
        }
    }
    return newObj;
}
export function randomNum(min: number, max: number): number {
    let num = Math.floor(Math.random() * (min - max) + max);
    return num;
}

export function getBrowserLang() {
    let browserLang = navigator.language ? navigator.language : navigator.browserLanguage;
    let defaultBrowserLang = '';
    if (
        browserLang.toLowerCase() === 'cn' ||
        browserLang.toLowerCase() === 'zh' ||
        browserLang.toLowerCase() === 'zh-cn'
    ) {
        defaultBrowserLang = 'zh';
    } else {
        defaultBrowserLang = 'en';
    }
    return defaultBrowserLang;
}
export function dateFormat(row: any, col: any, dataStr: any) {
    const date = new Date(dataStr);
    const y = date.getFullYear();
    let m: string | number = date.getMonth() + 1;
    m = m < 10 ? `0${String(m)}` : m;
    let d: string | number = date.getDate();
    d = d < 10 ? `0${String(d)}` : d;
    let h: string | number = date.getHours();
    h = h < 10 ? `0${String(h)}` : h;
    let minute: string | number = date.getMinutes();
    minute = minute < 10 ? `0${String(minute)}` : minute;
    let second: string | number = date.getSeconds();
    second = second < 10 ? `0${String(second)}` : second;
    return `${String(y)}-${String(m)}-${String(d)}   ${String(h)}:${String(minute)}:${String(second)}`;
}

//2016-01-12
export function dateFormatSimple(dataStr: any) {
    const date = new Date(dataStr);
    const y = date.getFullYear();
    let m: string | number = date.getMonth() + 1;
    m = m < 10 ? `0${String(m)}` : m;
    let d: string | number = date.getDate();
    d = d < 10 ? `0${String(d)}` : d;
    return `${String(y)}-${String(m)}-${String(d)}`;
}

// 20221013151302
export function dateFormatForName(dataStr: any) {
    const date = new Date(dataStr);
    const y = date.getFullYear();
    let m: string | number = date.getMonth() + 1;
    m = m < 10 ? `0${String(m)}` : m;
    let d: string | number = date.getDate();
    d = d < 10 ? `0${String(d)}` : d;
    let h: string | number = date.getHours();
    h = h < 10 ? `0${String(h)}` : h;
    let minute: string | number = date.getMinutes();
    minute = minute < 10 ? `0${String(minute)}` : minute;
    let second: string | number = date.getSeconds();
    second = second < 10 ? `0${String(second)}` : second;
    return `${String(y)}${String(m)}${String(d)}${String(h)}${String(minute)}${String(second)}`;
}

// 10-13 \n 15:13
export function dateFormatWithoutYear(dataStr: any) {
    const date = new Date(dataStr);
    let m: string | number = date.getMonth() + 1;
    m = m < 10 ? `0${String(m)}` : m;
    let d: string | number = date.getDate();
    d = d < 10 ? `0${String(d)}` : d;
    let h: string | number = date.getHours();
    h = h < 10 ? `0${String(h)}` : h;
    let minute: string | number = date.getMinutes();
    minute = minute < 10 ? `0${String(minute)}` : minute;
    return `${String(m)}-${String(d)}\n${String(h)}:${String(minute)}`;
}

// 20221013151302
export function dateFormatForSecond(dataStr: any) {
    const date = new Date(dataStr);
    let h: string | number = date.getHours();
    h = h < 10 ? `0${String(h)}` : h;
    let minute: string | number = date.getMinutes();
    minute = minute < 10 ? `0${String(minute)}` : minute;
    let second: string | number = date.getSeconds();
    second = second < 10 ? `0${String(second)}` : second;
    return `${String(h)}:${String(minute)}:${String(second)}`;
}

export function getRandomStr(e: number): string {
    const t = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    const a = t.length;
    let n = '';

    for (let i = 0; i < e; i++) {
        n += t.charAt(Math.floor(Math.random() * a));
    }
    return n;
}

/**
 * getSecureRandomStr 基于 crypto.getRandomValues 生成密码学安全随机字符串，
 * 用于安全入口码、SSH 私钥口令、各类凭据密码等安全敏感场景；
 * 非安全用途（如随机文件名）请继续使用 getRandomStr。
 */
export function getSecureRandomStr(n: number): string {
    const chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    // 拒绝采样消除模偏差（256 % chars.length != 0）
    const max = Math.floor(256 / chars.length) * chars.length;
    let result = '';
    while (result.length < n) {
        const bytes = new Uint8Array(n - result.length);
        crypto.getRandomValues(bytes);
        for (const b of bytes) {
            if (b < max) {
                result += chars.charAt(b % chars.length);
                if (result.length === n) {
                    break;
                }
            }
        }
    }
    return result;
}

export function getDBName(e: number): string {
    const t = 'abcdefhijkmnprstwxyz2345678';
    const a = t.length;
    let n = '';

    for (let i = 0; i < e; i++) {
        n += t.charAt(Math.floor(Math.random() * a));
    }
    return n;
}

export function loadZero(i: number) {
    return i < 10 ? '0' + i : '' + i;
}

export function computeSize(size: number): string {
    const num = 1024.0;
    if (size < num) return size + ' B';
    if (size < Math.pow(num, 2)) return formattedNumber((size / num).toFixed(2)) + ' KB';
    if (size < Math.pow(num, 3)) return formattedNumber((size / Math.pow(num, 2)).toFixed(2)) + ' MB';
    if (size < Math.pow(num, 4)) return formattedNumber((size / Math.pow(num, 3)).toFixed(2)) + ' GB';
    return formattedNumber((size / Math.pow(num, 4)).toFixed(2)) + ' TB';
}

export function splitSize(size: number): any {
    const num = 1024.0;
    if (size < num) return { size: Number(size), unit: 'B' };
    if (size < Math.pow(num, 2)) return { size: formattedNumber((size / num).toFixed(2)), unit: 'KB' };
    if (size < Math.pow(num, 3))
        return { size: formattedNumber((size / Number(Math.pow(num, 2).toFixed(2))).toFixed(2)), unit: 'MB' };
    if (size < Math.pow(num, 4))
        return { size: formattedNumber((size / Number(Math.pow(num, 3))).toFixed(2)), unit: 'GB' };
    return { size: formattedNumber((size / Number(Math.pow(num, 4))).toFixed(2)), unit: 'TB' };
}

export function formattedNumber(num: string) {
    return num.endsWith('.00') ? Number(num.slice(0, -3)) : Number(num);
}

export function computeSizeFromMB(size: number): string {
    const num = 1024.0;
    if (size < num) return size + ' MB';
    if (size < Math.pow(num, 2)) return (size / num).toFixed(2) + ' GB';
    return (size / Math.pow(num, 3)).toFixed(2) + ' TB';
}

export function computeSizeFromKB(size: number): string {
    const num = 1024.0;
    if (size < num) return size + ' KB';
    if (size < Math.pow(num, 2)) return (size / num).toFixed(2) + ' MB';
    if (size < Math.pow(num, 3)) return (size / Math.pow(num, 2)).toFixed(2) + ' GB';
    return (size / Math.pow(num, 3)).toFixed(2) + ' TB';
}
export function computeSizeFromByte(size: number): string {
    const num = 1024.0;
    if (size < num) return size + ' B';
    if (size < Math.pow(num, 2)) return (size / num).toFixed(2) + ' KB';
    if (size < Math.pow(num, 3)) return (size / Math.pow(num, 2)).toFixed(2) + ' MB';
    if (size < Math.pow(num, 4)) return (size / Math.pow(num, 3)).toFixed(2) + ' GB';
    return (size / Math.pow(num, 4)).toFixed(2) + ' TB';
}

export function computeSizeFromKBs(size: number): string {
    const num = 1024.0;
    if (size < num) return size + ' KB/s';
    if (size < Math.pow(num, 2)) return (size / num).toFixed(2) + ' MB/s';
    if (size < Math.pow(num, 3)) return (size / Math.pow(num, 2)).toFixed(2) + ' GB/s';
    return (size / Math.pow(num, 3)).toFixed(2) + ' TB/s';
}

let icons = new Map([
    ['.zip', 'p-file-zip'],
    ['.gz', 'p-file-zip'],
    ['.tar.bz2', 'p-file-zip'],
    ['.bz2', 'p-file-zip'],
    ['.xz', 'p-file-zip'],
    ['.tar', 'p-file-zip'],
    ['.tar.gz', 'p-file-zip'],
    ['.war', 'p-file-zip'],
    ['.tgz', 'p-file-zip'],
    ['.7z', 'p-file-zip'],
    ['.rar', 'p-file-zip'],
    ['.mp3', 'p-file-mp3'],
    ['.svg', 'p-file-svg'],
    ['.txt', 'p-file-txt'],
    ['.html', 'p-file-html'],
    ['.word', 'p-file-word'],
    ['.ppt', 'p-file-ppt'],
    ['.jpg', 'p-file-jpg'],
    ['.jpeg', 'p-file-jpg'],
    ['.png', 'p-file-png'],
    ['.xlsx', 'p-file-excel'],
    ['.doc', 'p-file-word'],
    ['.xls', 'p-file-excel'],
    ['.docx', 'p-file-word'],
    ['.pdf', 'p-file-pdf'],
    ['.bmp', 'p-file-png'],
    ['.gif', 'p-file-png'],
    ['.tiff', 'p-file-png'],
    ['.ico', 'p-file-png'],
    ['.webp', 'p-file-png'],
    ['.mp4', 'p-file-video'],
    ['.webm', 'p-file-video'],
    ['.mov', 'p-file-video'],
    ['.wmv', 'p-file-video'],
    ['.mkv', 'p-file-video'],
    ['.avi', 'p-file-video'],
    ['.wma', 'p-file-video'],
    ['.flv', 'p-file-video'],
    ['.wav', 'p-file-mp3'],
    ['.wma', 'p-file-mp3'],
    ['.ape', 'p-file-mp3'],
    ['.acc', 'p-file-mp3'],
    ['.ogg', 'p-file-mp3'],
    ['.flac', 'p-file-mp3'],
]);

export function getIcon(extension: string): string {
    if (icons.get(extension) != undefined) {
        const icon = icons.get(extension);
        return String(icon);
    } else {
        return 'p-file-normal';
    }
}

export function checkIp(value: string): boolean {
    if (value === '') {
        return true;
    }
    const reg =
        /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
    if (!reg.test(value) && value !== '') {
        return true;
    } else {
        return false;
    }
}

export function checkDomain(value: string): boolean {
    if (value === '') {
        return true;
    }
    const reg = /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/;
    if (!reg.test(value) && value !== '') {
        return true;
    } else {
        return false;
    }
}

export function isDomain(value: string): boolean {
    if (value === '') {
        return true;
    }
    const reg = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    if (value !== '' && reg.test(value)) {
        return true;
    } else {
        return false;
    }
}

export function checkIpV4V6(value: string): boolean {
    if (value === '') {
        return true;
    }
    const IPv4SegmentFormat = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
    const IPv4AddressFormat = `(${IPv4SegmentFormat}[.]){3}${IPv4SegmentFormat}`;
    const IPv4AddressRegExp = new RegExp(`^${IPv4AddressFormat}$`);
    const IPv6SegmentFormat = '(?:[0-9a-fA-F]{1,4})';
    const IPv6AddressRegExp = new RegExp(
        '^(' +
            `(?:${IPv6SegmentFormat}:){7}(?:${IPv6SegmentFormat}|:)|` +
            `(?:${IPv6SegmentFormat}:){6}(?:${IPv4AddressFormat}|:${IPv6SegmentFormat}|:)|` +
            `(?:${IPv6SegmentFormat}:){5}(?::${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,2}|:)|` +
            `(?:${IPv6SegmentFormat}:){4}(?:(:${IPv6SegmentFormat}){0,1}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,3}|:)|` +
            `(?:${IPv6SegmentFormat}:){3}(?:(:${IPv6SegmentFormat}){0,2}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,4}|:)|` +
            `(?:${IPv6SegmentFormat}:){2}(?:(:${IPv6SegmentFormat}){0,3}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,5}|:)|` +
            `(?:${IPv6SegmentFormat}:){1}(?:(:${IPv6SegmentFormat}){0,4}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,6}|:)|` +
            `(?::((?::${IPv6SegmentFormat}){0,5}:${IPv4AddressFormat}|(?::${IPv6SegmentFormat}){1,7}|:))` +
            ')(%[0-9a-zA-Z-.:]{1,})?$',
    );
    if (!IPv4AddressRegExp.test(value) && !IPv6AddressRegExp.test(value) && value !== '') {
        return true;
    } else {
        return false;
    }
}

export function checkIpV6(value: string): boolean {
    if (value === '' || typeof value === 'undefined' || value == null) {
        return true;
    } else {
        const IPv4SegmentFormat = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
        const IPv4AddressFormat = `(${IPv4SegmentFormat}[.]){3}${IPv4SegmentFormat}`;
        const IPv6SegmentFormat = '(?:[0-9a-fA-F]{1,4})';
        const IPv6AddressRegExp = new RegExp(
            '^(' +
                `(?:${IPv6SegmentFormat}:){7}(?:${IPv6SegmentFormat}|:)|` +
                `(?:${IPv6SegmentFormat}:){6}(?:${IPv4AddressFormat}|:${IPv6SegmentFormat}|:)|` +
                `(?:${IPv6SegmentFormat}:){5}(?::${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,2}|:)|` +
                `(?:${IPv6SegmentFormat}:){4}(?:(:${IPv6SegmentFormat}){0,1}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,3}|:)|` +
                `(?:${IPv6SegmentFormat}:){3}(?:(:${IPv6SegmentFormat}){0,2}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,4}|:)|` +
                `(?:${IPv6SegmentFormat}:){2}(?:(:${IPv6SegmentFormat}){0,3}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,5}|:)|` +
                `(?:${IPv6SegmentFormat}:){1}(?:(:${IPv6SegmentFormat}){0,4}:${IPv4AddressFormat}|(:${IPv6SegmentFormat}){1,6}|:)|` +
                `(?::((?::${IPv6SegmentFormat}){0,5}:${IPv4AddressFormat}|(?::${IPv6SegmentFormat}){1,7}|:))` +
                ')(%[0-9a-zA-Z-.:]{1,})?$',
        );
        if (!IPv6AddressRegExp.test(value) && value !== '') {
            return true;
        } else {
            return false;
        }
    }
}

export function checkCidr(value: string): boolean {
    if (value === '') {
        return true;
    }
    const reg =
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
    if (!reg.test(value) && value !== '') {
        return true;
    } else {
        return false;
    }
}
export function checkCidrV6(value: string): boolean {
    if (value === '') {
        return true;
    }
    if (checkIpV6(value.split('/')[0])) {
        return true;
    }
    const reg = /^(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$/;
    if (!reg.test(value.split('/')[1])) {
        return true;
    }
    return false;
}

export function checkPort(value: string): boolean {
    if (Number(value) <= 0) {
        return true;
    }
    const reg = /^([1-9](\d{0,3}))$|^([1-5]\d{4})$|^(6[0-4]\d{3})$|^(65[0-4]\d{2})$|^(655[0-2]\d)$|^(6553[0-5])$/;
    return !reg.test(value) && value !== '';
}

export function getProvider(provider: string): string {
    switch (provider) {
        case 'dnsAccount':
            return i18n.global.t('website.dnsAccount');
        case 'dnsManual':
            return i18n.global.t('website.dnsManual');
        case 'http':
            return 'HTTP';
        case 'selfSigned':
            return i18n.global.t('ssl.selfSigned');
        default:
            return i18n.global.t('ssl.manualCreate');
    }
}

export function splitTime(item: string): any {
    if (item.indexOf('s') !== -1) {
        return { time: Number(item.replaceAll('s', '')), unit: 's' };
    }
    if (item.indexOf('m') !== -1) {
        return { time: Number(item.replaceAll('m', '')), unit: 'm' };
    }
    if (item.indexOf('h') !== -1) {
        return { time: Number(item.replaceAll('h', '')), unit: 'h' };
    }
    if (item.indexOf('d') !== -1) {
        return { time: Number(item.replaceAll('d', '')), unit: 'd' };
    }
    if (item.indexOf('y') !== -1) {
        return { time: Number(item.replaceAll('y', '')), unit: 'y' };
    }
    return { time: Number(item), unit: 's' };
}
export function transTimeUnit(val: string): any {
    if (val.indexOf('s') !== -1) {
        return val.replaceAll('s', i18n.global.t('commons.units.second'));
    }
    if (val.indexOf('m') !== -1) {
        return val.replaceAll('m', i18n.global.t('commons.units.minute'));
    }
    if (val.indexOf('h') !== -1) {
        return val.replaceAll('h', i18n.global.t('commons.units.hour'));
    }
    if (val.indexOf('d') !== -1) {
        return val.replaceAll('d', i18n.global.t('commons.units.day'));
    }
    if (val.indexOf('y') !== -1) {
        return val.replaceAll('y', i18n.global.t('commons.units.year'));
    }
    return val + i18n.global.t('commons.units.second');
}

export function splitHttp(url: string) {
    if (url.indexOf('https://') != -1) {
        return { proto: 'https', url: url.replaceAll('https://', '') };
    }
    if (url.indexOf('http://') != -1) {
        return { proto: 'http', url: url.replaceAll('http://', '') };
    }
    return { proto: '', url: url };
}
export function spliceHttp(proto: string, url: string) {
    return proto + '://' + url.replaceAll('https://', '').replaceAll('http://', '');
}

export function getAge(d1: string): string {
    const dateBegin = new Date(d1);
    const dateEnd = new Date();
    const dateDiff = dateEnd.getTime() - dateBegin.getTime();
    const dayDiff = Math.floor(dateDiff / (24 * 3600 * 1000));
    const leave1 = dateDiff % (24 * 3600 * 1000);
    const hours = Math.floor(leave1 / (3600 * 1000));
    const leave2 = leave1 % (3600 * 1000);
    const minutes = Math.floor(leave2 / (60 * 1000));

    let res = '';
    if (dayDiff > 0) {
        res += String(dayDiff) + ' ' + i18n.global.t('commons.units.day', dayDiff) + ' ';
        if (hours <= 0) {
            return res;
        }
    }
    if (hours > 0) {
        res += String(hours) + ' ' + i18n.global.t('commons.units.hour', hours) + ' ';
        return res;
    }
    if (minutes > 0) {
        res += String(minutes) + ' ' + i18n.global.t('commons.units.minute', minutes);
        return res;
    }
    return i18n.global.t('app.less1Minute');
}

export function isJson(str: string) {
    try {
        if (typeof JSON.parse(str) === 'object') {
            return true;
        }
    } catch {
        return false;
    }
}

export function toLowerCase(str: string) {
    return str.toLowerCase();
}

export function downloadFile(filePath: string) {
    let url = `${import.meta.env.VITE_API_URL as string}/files/download?`;
    let path = encodeURIComponent(filePath);
    window.open(url + 'path=' + path, '_blank');
}

/**
 * downloadWithBlob 创建隐藏 <a> 触发 blob 下载，并在点击后（setTimeout 0 延迟，
 * 确保 Safari 等浏览器下载已启动）revokeObjectURL 释放内存。
 */
export function downloadWithBlob(blob: Blob, fileName: string) {
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = downloadUrl;
    a.download = fileName;
    const event = new MouseEvent('click');
    a.dispatchEvent(event);
    setTimeout(() => {
        window.URL.revokeObjectURL(downloadUrl);
    }, 0);
}

export function downloadWithContent(content: string, fileName: string) {
    downloadWithBlob(new Blob([content]), fileName);
}

/**
 * openExternalLink 在新窗口打开外部链接：仅放行 http/https 协议（其余协议
 * 静默忽略点击，不报错），并通过 noopener,noreferrer 隔离 opener，
 * 防止新页面对本页的反向标签劫持。
 */
export function openExternalLink(url: string) {
    if (!/^https?:\/\//i.test(url)) {
        return;
    }
    window.open(url, '_blank', 'noopener,noreferrer');
}
export function getDateStr() {
    let now: Date = new Date();

    let year: number = now.getFullYear();
    let month: number = now.getMonth() + 1;
    let date: number = now.getDate();
    let hours: number = now.getHours();
    let minutes: number = now.getMinutes();
    let seconds: number = now.getSeconds();

    let timestamp: string = `${year}-${month < 10 ? '0' + month : month}-${date < 10 ? '0' + date : date}-${
        hours < 10 ? '0' + hours : hours
    }-${minutes < 10 ? '0' + minutes : minutes}-${seconds < 10 ? '0' + seconds : seconds}`;

    return timestamp;
}

export function getAccountName(type: string) {
    for (const i of AcmeAccountTypes) {
        if (i.value === type) {
            return i.label;
        }
    }
    return '';
}

export function getKeyName(type: string) {
    for (const i of KeyTypes) {
        if (i.value === type) {
            return i.label;
        }
    }
    return '';
}

export function getDNSName(type: string) {
    for (const i of DNSTypes) {
        if (i.value === type) {
            return i.label;
        }
    }
    return '';
}

export async function copyText(content: string) {
    try {
        await toClipboard(content);
        MsgSuccess(i18n.global.t('commons.msg.copySuccess'));
    } catch (e) {
        MsgError(i18n.global.t('commons.msg.copyFailed'));
    }
}

export function getAction(action: string) {
    if (action == '') {
        return '';
    }
    return i18n.global.t(`xpack.waf.${action}`);
}

export function getLanguage() {
    return localStorage.getItem('lang') || 'zh';
}

export function emptyLineFilter(str: string, spilt: string) {
    let list = str.split(spilt);
    let results = [];
    for (let i = 0; i < list.length; i++) {
        if (list[i].trim() !== '') {
            results.push(list[i]);
        }
    }
    return results.join(spilt);
}

// 文件类型映射
let fileTypes = {
    image: ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.svg', '.webp'],
    compress: ['.zip', '.rar', '.gz', '.war', '.tgz', '.7z', '.tar.gz', '.tar', '.bz2', '.xz', '.tar.bz2', '.tar.xz'],
    video: ['.mp4', '.webm', '.mov', '.wmv', '.mkv', '.avi', '.wma', '.flv'],
    audio: ['.mp3', '.wav', '.wma', '.ape', '.acc', '.ogg', '.flac'],
    pdf: ['.pdf'],
    word: ['.doc', '.docx'],
    excel: ['.xls', '.xlsx'],
    text: ['.iso', '.tiff', '.exe', '.so', '.bz', '.dmg', '.apk', '.pptx', '.ppt', '.xlsb'],
};

export const getFileType = (extension: string) => {
    let type = 'text';
    Object.entries(fileTypes).forEach(([key, extensions]) => {
        if (extensions.includes(extension.toLowerCase())) {
            type = key;
        }
    });
    return type;
};

function getCookie(name: string) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function rsaEncrypt(data: string, publicKey: string) {
    if (!data) {
        return data;
    }
    const jsEncrypt = new JSEncrypt();
    jsEncrypt.setPublicKey(publicKey);
    return jsEncrypt.encrypt(data);
}

function aesEncrypt(data: string, key: string) {
    const keyBytes = CryptoJS.enc.Utf8.parse(key);
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(data, keyBytes, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });
    return iv.toString(CryptoJS.enc.Base64) + ':' + encrypted.toString();
}

function urlDecode(value: string): string {
    return decodeURIComponent(value.replace(/\+/g, ' '));
}

function generateAESKey(): string {
    const keyLength = 16;
    const randomBytes = new Uint8Array(keyLength);
    crypto.getRandomValues(randomBytes);
    return Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export const encryptPassword = (password: string) => {
    if (!password) {
        return '';
    }
    let rsaPublicKeyText = getCookie('panel_public_key');
    if (!rsaPublicKeyText) {
        console.error('RSA public key not found, refuse to transmit plaintext password');
        return '';
    }
    rsaPublicKeyText = urlDecode(rsaPublicKeyText);

    const aesKey = generateAESKey();
    rsaPublicKeyText = rsaPublicKeyText.replaceAll('"', '');
    const rsaPublicKey = atob(rsaPublicKeyText);
    const keyCipher = rsaEncrypt(aesKey, rsaPublicKey);
    const passwordCipher = aesEncrypt(password, aesKey);
    return `${keyCipher}:${passwordCipher}`;
};

/**
 * escapeHtml 对字符串中的 HTML 特殊字符做实体转义。
 * 用于把用户可控数据安全地插入到 v-html / i18n 插值模板中（如删除确认提示），
 * 防止标签注入导致 XSS；模板自身的标签（如 <span style="color:red">）不受影响。
 */
export function escapeHtml(value: string): string {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * sanitizeTerminalPath 校验来自不可信来源（如 URL query ?path=）的路径，仅当其
 * 可以安全地拼进 shell 命令（如 `cd "${path}"`）时原样返回，否则返回 null。
 * 规则（白名单优先，未列出的字符一律拒绝）：
 * 1. 必须是以 / 开头的绝对路径；
 * 2. 仅允许 A-Za-z0-9 . _ - / ~ 以及空格（空格用于兼容含空格的合法目录，
 *    双引号、单引号、反引号、$、;、|、&、括号、重定向、反斜杠、换行、Tab 等
 *    shell 元字符均在白名单之外，天然被拒绝）；
 * 3. 拒绝包含 .. 路径分量。
 */
export function sanitizeTerminalPath(path: string): string | null {
    if (typeof path !== 'string' || path.length === 0 || !path.startsWith('/')) {
        return null;
    }
    const safeChars = /^[A-Za-z0-9 ._\-/~]+$/;
    if (!safeChars.test(path)) {
        return null;
    }
    if (path.split('/').includes('..')) {
        return null;
    }
    return path;
}
