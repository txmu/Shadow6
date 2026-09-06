#!/usr/bin/env bash
set -euo pipefail

print_legal_warning() {
    printf '%s\n' \
        '================================================================================' \
        '                Shadow6 中国大陆地区使用者法律与合规警告' \
        '================================================================================' \
        '请在继续前完整阅读。本提示不构成法律意见，也不替代单位审批、授权文件、' \
        '网络接入服务协议、行业监管要求或专业法律咨询。法律法规和监管要求可能变化，' \
        '使用者有义务在每次部署前自行核实最新有效规定。' \
        '' \
        '一、《中华人民共和国网络安全法》（根据2025年10月28日决定修正，' \
        '    2026年1月1日起施行）相关要求摘要：' \
        '  1. 第十三条要求个人和组织使用网络时遵守宪法法律、公共秩序和社会公德，' \
        '     不得危害网络安全，不得侵害国家安全、社会公共利益及他人合法权益。' \
        '  2. 第二十三条要求网络运营者落实安全管理、访问控制、日志、数据保护等义务。' \
        '  3. 第二十四条要求网络产品和服务符合强制性标准；发现安全缺陷、漏洞等风险' \
        '     时应及时采取补救措施，并按规定告知、报告。' \
        '  4. 第二十九条禁止非法侵入他人网络、干扰网络正常功能、窃取网络数据，' \
        '     禁止提供专门用于相关危害活动的程序或工具，也禁止明知而提供帮助。' \
        '' \
        '二、《中华人民共和国密码法》相关要求摘要：' \
        '  1. 第八条允许公民、法人和其他组织依法使用商用密码保护网络与信息安全。' \
        '  2. 第十二条禁止窃取他人加密保护的信息、非法侵入他人的密码保障系统，' \
        '     以及利用密码从事危害国家安全、社会公共利益或他人合法权益的活动。' \
        '  3. 第三十二条规定，违反第十二条的行为将依照网络安全法及其他法律法规' \
        '     追究责任；构成犯罪或造成损害的，还可能承担刑事、行政或民事责任。' \
        '' \
        '三、使用边界：' \
        '  * 仅可连接由本人所有或已取得明确书面授权的设备、账号、网络和数据。' \
        '  * 不得把本工具用于规避依法实施的网络管理措施、未授权访问、漏洞利用、' \
        '    流量劫持、数据窃取、隐私侵害、破坏业务可用性或其他违法违规活动。' \
        '  * 涉及个人信息、重要数据、关键信息基础设施、商用密码或跨境数据活动时，' \
        '    使用者须另行履行适用的审批、评估、备案和保护义务。' \
        '  * 本确认只能记录使用者的明确承诺，不能使未授权或违法行为合法化。' \
        '' \
        '现行文本核对来源：中国人大网、国家保密局等国家机关公开法律文本。' \
        '================================================================================'
}

require_manual_agreement() {
    if [[ ! -t 0 || ! -t 1 ]]; then
        printf '%s\n' '拒绝继续：必须在交互式终端内由使用者本人手动确认，禁止管道或重定向确认。' >&2
        return 3
    fi
    local pledge reply
    pledge='本人承诺仅在境内合法合规使用本工具，不用于绕过国家防火墙（翻墙）或进行非法渗透测试，否则后果自负'
    printf '%s\n' "$pledge"
    printf '%s' '如同意并承诺遵守，请手动输入 Y 或 Agree：'
    IFS= read -r reply
    if [[ "$reply" != Y && "$reply" != Agree ]]; then
        printf '%s\n' '未获得有效确认，操作已取消。' >&2
        return 3
    fi
    printf '%s\n' '确认已接受。'
}

usage() {
    printf '%s\n' \
        'Usage: 中国内地用户必须执行.sh --show|--apply|--remove' \
        '  --show    显示拟议的本机 OUTPUT 限制（默认；不修改系统）' \
        '  --apply   幂等添加缺失规则；需要 root 和 iptables' \
        '  --remove  删除本脚本此前添加的规则'
}

print_legal_warning
require_manual_agreement

ports=(1080 3128 7890 8388 10808)
comment=Shadow6_Compliance_Block
action=${1:---show}
if [[ $# -gt 1 ]]; then
    usage >&2
    exit 2
fi

case "$action" in
    --show)
        for port in "${ports[@]}"; do
            printf 'iptables -A OUTPUT -p tcp --dport %s -m comment --comment %s -j REJECT\n' "$port" "$comment"
        done
        ;;
    --apply|--remove)
        if [[ $EUID -ne 0 ]]; then
            printf '%s\n' '此操作需要 root 权限。' >&2
            exit 1
        fi
        command -v iptables >/dev/null || { printf '%s\n' '未安装 iptables。' >&2; exit 1; }
        for port in "${ports[@]}"; do
            rule=(-p tcp --dport "$port" -m comment --comment "$comment" -j REJECT)
            if [[ "$action" == --apply ]]; then
                if ! iptables -C OUTPUT "${rule[@]}" 2>/dev/null; then
                    iptables -A OUTPUT "${rule[@]}"
                fi
            else
                while iptables -C OUTPUT "${rule[@]}" 2>/dev/null; do
                    iptables -D OUTPUT "${rule[@]}"
                done
            fi
        done
        ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
