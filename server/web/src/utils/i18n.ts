/**
 * Internationalization (i18n) utility
 * Provides translation support for English and Chinese
 */

export type Language = 'en' | 'zh';

export interface Translations {
  [key: string]: {
    en: string;
    zh: string;
  };
}

// Translation dictionary
const translations: Translations = {
  // SystemTable
  'allSystems': { en: 'All Servers', zh: '所有服务器' },
  'updatedInRealTime': { en: 'Updated in real time. Click on a server to view information.', zh: '实时更新，点击服务器查看详细信息。' },
  'filter': { en: 'Filter...', zh: '筛选...' },
  'columns': { en: 'Columns', zh: '列' },
  'sortBy': { en: 'Sort by', zh: '排序方式' },
  'name': { en: 'Name', zh: '名称' },
  'time': { en: 'Uptime', zh: '运行时间' },
  'location': { en: 'Location', zh: '位置' },
  'cpu': { en: 'CPU', zh: 'CPU' },
  'memory': { en: 'Memory', zh: '内存' },
  'disk': { en: 'Disk', zh: '磁盘' },
  'net': { en: 'Net', zh: '网络' },
  'os': { en: 'OS', zh: '系统' },
  'system': { en: 'Server', zh: '服务器' },
  'noSystemsFound': { en: 'No servers found', zh: '未找到服务器' },
  'systemsWillAppear': { en: 'Servers will appear here once agents start reporting', zh: '代理开始报告后，服务器将显示在这里' },
  'cpuInformation': { en: 'CPU Information:', zh: 'CPU 信息:' },
  'memoryInfo': { en: 'Memory:', zh: '内存:' },
  'swapPartition': { en: 'Swap Partition:', zh: '交换分区:' },
  'diskInformation': { en: 'Disk Information:', zh: '磁盘信息:' },
  'copySystemName': { en: 'Copy server name', zh: '复制服务器名称' },
  
  // AdminDashboard
  'systemList': { en: 'Server List', zh: '服务器列表' },
  'addSystem': { en: 'Add Server', zh: '添加服务器' },
  'refresh': { en: 'Refresh', zh: '刷新' },
  'loadingSystems': { en: 'Loading servers...', zh: '加载服务器中...' },
  'systemName': { en: 'Server Name', zh: '服务器名称' },
  'note': { en: 'Note:', zh: '注意:' },
  'noteContent': { en: 'IP addresses, location, OS and metrics are automatically updated by the agent and cannot be edited manually.', zh: 'IP 地址、位置、操作系统和指标由代理自动更新，无法手动编辑。' },
  'cancel': { en: 'Cancel', zh: '取消' },
  'updateSystem': { en: 'Save', zh: '保存' },
  'deleteSystem': { en: 'Delete Server', zh: '删除服务器' },
  'editSystem': { en: 'Edit Server', zh: '编辑服务器' },
  'addNewSystem': { en: 'Add New Server', zh: '添加新服务器' },
  'deleteConfirmation': { en: 'Are you sure you want to delete this server?', zh: '您确定要删除此服务器吗？' },
  'thisActionCannotBeUndone': { en: 'This action cannot be undone.', zh: '此操作无法撤销。' },
  'ipv4': { en: 'IPv4:', zh: 'IPv4:' },
  'ipv6': { en: 'IPv6:', zh: 'IPv6:' },
  'in': { en: 'In:', zh: '入站:' },
  'out': { en: 'Out:', zh: '出站:' },
  'exportData': { en: 'Export Data', zh: '导出数据' },
  'clearCache': { en: 'Clear Cache', zh: '清除缓存' },
  'backToDashboard': { en: 'Back to Dashboard', zh: '返回仪表板' },
  'manageYourDatabase': { en: 'Manage your database', zh: '管理您的数据库' },
  'databaseActions': { en: 'Database Actions', zh: '数据库操作' },
  'displayNameForThisSystem': { en: 'Display name for this server', zh: '此服务器的显示名称' },
  'myServer': { en: 'My Server', zh: '我的服务器' },
  'areYouSureYouWantToDelete': { en: 'Are you sure you want to delete', zh: '您确定要删除' },
  'delete': { en: 'Delete', zh: '删除' },
};

let currentLanguage: Language = 'en';

/**
 * Get current language: the visitor's stored choice, else the one the page
 * head picked for <html lang> from the browser language (as the navbar does).
 */
export function getLanguage(): Language {
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('preferred-language');
    if (stored === 'zh' || stored === 'en') {
      return stored;
    }
    return document.documentElement.lang === 'zh' ? 'zh' : 'en';
  }
  return currentLanguage;
}

/**
 * Set language
 */
export function setLanguage(lang: Language): void {
  currentLanguage = lang;
  if (typeof window !== 'undefined') {
    localStorage.setItem('preferred-language', lang);
    document.documentElement.lang = lang;
  }
}

/**
 * Translate a key to the current language
 */
export function t(key: string): string {
  const lang = getLanguage();
  const translation = translations[key];
  if (!translation) {
    return key;
  }
  return translation[lang] || translation.en;
}

/**
 * Initialize i18n system
 */
export function initI18n(): void {
  if (typeof window !== 'undefined') {
    // Read, not stored: a visitor who never picked a language keeps
    // following the browser's. (Storing it here pinned every first visit to
    // English while the navbar followed the browser.)
    currentLanguage = getLanguage();
    
    // Listen for language changes. The navbar's switch carries the language;
    // the browser fires a plain 'languagechange' of its own when the user
    // changes the browser's languages, which is not a choice for this page.
    window.addEventListener('languagechange', (e: any) => {
      const newLang = e.detail?.language;
      if (newLang !== 'zh' && newLang !== 'en') return;
      setLanguage(newLang as Language);
      // Trigger translation update
      window.dispatchEvent(new CustomEvent('translate'));
    });
  }
}

