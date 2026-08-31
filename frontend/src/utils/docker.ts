import { isJson } from './util';

export function formatImageStdout(stdout: string) {
    let lines = stdout.split('\r\n');
    for (let i = 0; i < lines.length; i++) {
        if (isJson(lines[i])) {
            const data = JSON.parse(lines[i]);
            // docker build/pull 流式日志的错误行形如
            // {"errorDetail":{"message":"..."},"error":"..."}，优先取 errorDetail.message，
            // 缺失时逐级回退，避免错误详情被空值覆盖
            if (data.errorDetail || data.error) {
                lines[i] = data.errorDetail?.message || data.errorDetail || data.error || 'unknown error';
                continue;
            }
            if (data.stream) {
                lines[i] = data.stream;
                continue;
            }
            if (data.id) {
                lines[i] = data.id + ': ' + data.status;
            } else {
                lines[i] = data.status;
            }
            if (data.progress) {
                lines[i] = lines[i] + data.progress;
            }
        }
    }
    return lines.join('\r\n');
}
