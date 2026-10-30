// Interface text. English is complete; the other languages translate the
// menus, headings and settings, and fall back to English for the rest.

import { state } from "./state";

const en = {
  appName: "Project DAD (Data Anomaly Detection) Console",
  appShort: "SMRT",
  "nav.dashboard": "Dashboard",
  "nav.analyze": "Analyze",
  "nav.patterns": "Patterns",
  "nav.sigma": "Sigma",
  "nav.models": "Models",
  "nav.data": "Data",
  "nav.review": "Review", "nav.audit": "Audit", "nav.explain": "Explain", "nav.profiles": "Profiles",
  "nav.datasets": "Datasets",
  "nav.docs": "Documentation",
  "nav.settings": "Settings",
  "nav.simple": "Check logs",
  "nav.reports": "Reports",
  "group.overview": "Overview",
  "group.prepare": "Prepare",
  "group.detect": "Detect",
  "group.investigate": "Investigate",
  "group.report": "Report",
  "group.console": "Console",
  "mode.simple": "Simple",
  "mode.advanced": "Advanced",
  "mode.switch": "Switch to Advanced",
  "settings.mode": "Console",
  "llm.label": "Local model",
  "llm.online": "Ollama running",
  "llm.offline": "Ollama not running",
  "llm.refresh": "Check again",
  "common.save": "Save",
  "settings.language": "Language",
  "settings.theme": "Appearance",
  "settings.theme.light": "Light",
  "settings.theme.dark": "Dark",
  "settings.theme.system": "Same as the system",
  "settings.font": "Font",
  "settings.font.installed": "Installed font",
  "settings.fontSize": "Text size",
  "settings.animations": "Animations",
  "settings.animations.all": "All",
  "settings.animations.noArrival": "Skip ending",
  "settings.pack": "Animation pack",
  "settings.pack.transit": "Transit",
  "settings.pack.desk": "Desk",
  "settings.pack.commuter": "Commuter",
  "settings.animations.none": "None",
};

type Key = keyof typeof en;
type Table = Partial<Record<Key, string>>;

const zh: Table = {
  "nav.dashboard": "仪表板", "nav.analyze": "分析", "nav.patterns": "模式", "nav.models": "模型", "nav.data": "数据", "nav.review": "审查", "nav.audit": "审计", "nav.explain": "解释", "nav.profiles": "画像", "nav.datasets": "数据集", "nav.docs": "文档", "nav.settings": "设置", "nav.simple": "检查日志", "nav.reports": "报告", "mode.simple": "简单", "mode.advanced": "高级", "mode.switch": "切换到高级", "settings.mode": "控制台",
  "group.overview": "概览", "group.prepare": "准备", "group.detect": "检测", "group.investigate": "调查", "group.report": "报告", "group.console": "控制台",
  "llm.label": "本地模型", "llm.online": "Ollama 运行中", "llm.offline": "Ollama 未运行", "llm.refresh": "重新检查",
  "common.save": "保存", "settings.language": "语言", "settings.theme": "外观", "settings.theme.light": "浅色",
  "settings.theme.dark": "深色", "settings.theme.system": "跟随系统", "settings.font": "字体", "settings.font.installed": "已安装字体", "settings.fontSize": "文字大小",
  "settings.animations": "动画", "settings.animations.all": "全部", "settings.animations.noArrival": "跳过结尾", "settings.animations.none": "无",
  "settings.pack": "动画主题", "settings.pack.transit": "交通", "settings.pack.desk": "办公桌", "settings.pack.commuter": "通勤",
};

const ms: Table = {
  "nav.dashboard": "Papan Pemuka", "nav.analyze": "Analisis", "nav.patterns": "Corak", "nav.models": "Model", "nav.data": "Data", "nav.review": "Semakan", "nav.audit": "Audit", "nav.explain": "Penerangan", "nav.profiles": "Profil", "nav.datasets": "Set Data", "nav.docs": "Dokumentasi", "nav.settings": "Tetapan", "nav.simple": "Semak log", "nav.reports": "Laporan", "mode.simple": "Ringkas", "mode.advanced": "Lanjutan", "mode.switch": "Tukar ke Lanjutan", "settings.mode": "Konsol",
  "group.overview": "Gambaran", "group.prepare": "Persediaan", "group.detect": "Pengesanan", "group.investigate": "Siasatan", "group.report": "Laporan", "group.console": "Konsol",
  "llm.label": "Model tempatan", "llm.online": "Ollama sedang berjalan", "llm.offline": "Ollama tidak berjalan", "llm.refresh": "Semak semula",
  "common.save": "Simpan", "settings.language": "Bahasa", "settings.theme": "Paparan", "settings.theme.light": "Cerah",
  "settings.theme.dark": "Gelap", "settings.theme.system": "Ikut sistem", "settings.font": "Fon", "settings.font.installed": "Fon terpasang", "settings.fontSize": "Saiz teks",
  "settings.animations": "Animasi", "settings.animations.all": "Semua", "settings.animations.noArrival": "Langkau penamat", "settings.animations.none": "Tiada",
  "settings.pack": "Pek animasi", "settings.pack.transit": "Pengangkutan", "settings.pack.desk": "Meja", "settings.pack.commuter": "Penumpang",
};

const ta: Table = {
  "nav.dashboard": "முகப்புப் பலகை", "nav.analyze": "பகுப்பாய்வு", "nav.patterns": "வடிவங்கள்", "nav.models": "மாதிரிகள்", "nav.data": "தரவு", "nav.review": "மதிப்பாய்வு", "nav.audit": "தணிக்கை", "nav.explain": "விளக்கம்", "nav.profiles": "சுயவிவரங்கள்", "nav.datasets": "தரவுத்தொகுப்புகள்", "nav.docs": "ஆவணங்கள்", "nav.settings": "அமைப்புகள்", "nav.simple": "பதிவுகளைச் சரிபார்", "nav.reports": "அறிக்கைகள்", "mode.simple": "எளிய", "mode.advanced": "மேம்பட்ட", "mode.switch": "மேம்பட்டதுக்கு மாறு", "settings.mode": "கன்சோல்",
  "group.overview": "மேலோட்டம்", "group.prepare": "தயாரிப்பு", "group.detect": "கண்டறிதல்", "group.investigate": "விசாரணை", "group.report": "அறிக்கை", "group.console": "கன்சோல்",
  "llm.label": "உள்ளூர் மாதிரி", "llm.online": "Ollama இயங்குகிறது", "llm.offline": "Ollama இயங்கவில்லை", "llm.refresh": "மீண்டும் சரிபார்",
  "common.save": "சேமி", "settings.language": "மொழி", "settings.theme": "தோற்றம்", "settings.theme.light": "வெளிர்",
  "settings.theme.dark": "இருண்ட", "settings.theme.system": "கணினியைப் போல", "settings.font": "எழுத்துரு", "settings.font.installed": "நிறுவப்பட்ட எழுத்துரு", "settings.fontSize": "எழுத்து அளவு",
  "settings.animations": "அசைவூட்டங்கள்", "settings.animations.all": "அனைத்தும்", "settings.animations.noArrival": "முடிவைத் தவிர்", "settings.animations.none": "எதுவும் இல்லை",
  "settings.pack": "அசைவூட்டத் தொகுப்பு", "settings.pack.transit": "போக்குவரத்து", "settings.pack.desk": "மேசை", "settings.pack.commuter": "பயணி",
};

const ja: Table = {
  "nav.dashboard": "ダッシュボード", "nav.analyze": "分析", "nav.patterns": "パターン", "nav.models": "モデル", "nav.data": "データ", "nav.review": "レビュー", "nav.audit": "監査", "nav.explain": "説明", "nav.profiles": "プロファイル", "nav.datasets": "データセット", "nav.docs": "ドキュメント", "nav.settings": "設定", "nav.simple": "ログを確認", "nav.reports": "レポート", "mode.simple": "シンプル", "mode.advanced": "詳細", "mode.switch": "詳細に切り替え", "settings.mode": "コンソール",
  "group.overview": "概要", "group.prepare": "準備", "group.detect": "検知", "group.investigate": "調査", "group.report": "報告", "group.console": "コンソール",
  "llm.label": "ローカルモデル", "llm.online": "Ollama 実行中", "llm.offline": "Ollama 停止中", "llm.refresh": "再確認",
  "common.save": "保存", "settings.language": "言語", "settings.theme": "外観", "settings.theme.light": "ライト",
  "settings.theme.dark": "ダーク", "settings.theme.system": "システムに合わせる", "settings.font": "フォント", "settings.font.installed": "インストール済みフォント", "settings.fontSize": "文字サイズ",
  "settings.animations": "アニメーション", "settings.animations.all": "すべて", "settings.animations.noArrival": "終わりを省略", "settings.animations.none": "なし",
  "settings.pack": "アニメーションパック", "settings.pack.transit": "交通", "settings.pack.desk": "デスク", "settings.pack.commuter": "通勤",
};

const ko: Table = {
  "nav.dashboard": "대시보드", "nav.analyze": "분석", "nav.patterns": "패턴", "nav.models": "모델", "nav.data": "데이터", "nav.review": "검토", "nav.audit": "감사", "nav.explain": "설명", "nav.profiles": "프로필", "nav.datasets": "데이터셋", "nav.docs": "문서", "nav.settings": "설정", "nav.simple": "로그 확인", "nav.reports": "보고서", "mode.simple": "간단", "mode.advanced": "고급", "mode.switch": "고급으로 전환", "settings.mode": "콘솔",
  "group.overview": "개요", "group.prepare": "준비", "group.detect": "탐지", "group.investigate": "조사", "group.report": "보고", "group.console": "콘솔",
  "llm.label": "로컬 모델", "llm.online": "Ollama 실행 중", "llm.offline": "Ollama 중지됨", "llm.refresh": "다시 확인",
  "common.save": "저장", "settings.language": "언어", "settings.theme": "화면 모드", "settings.theme.light": "라이트",
  "settings.theme.dark": "다크", "settings.theme.system": "시스템 설정", "settings.font": "글꼴", "settings.font.installed": "설치된 글꼴", "settings.fontSize": "글자 크기",
  "settings.animations": "애니메이션", "settings.animations.all": "모두", "settings.animations.noArrival": "마무리 건너뛰기", "settings.animations.none": "없음",
  "settings.pack": "애니메이션 팩", "settings.pack.transit": "교통", "settings.pack.desk": "책상", "settings.pack.commuter": "통근",
};

export const LANGUAGES: [string, string][] = [
  ["en", "English"],
  ["ms", "Bahasa Melayu"],
  ["zh", "中文（简体）"],
  ["ta", "தமிழ்"],
  ["ja", "日本語"],
  ["ko", "한국어"],
];
const TABLES: Record<string, Table> = { en, zh, ms, ta, ja, ko };

export function t(key: Key): string {
  return TABLES[state.settings?.language ?? "en"]?.[key] ?? en[key];
}
