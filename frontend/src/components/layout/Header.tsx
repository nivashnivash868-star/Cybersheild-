import React, { useState } from 'react';
import {
  Search, Bell, Sun, Moon, LogOut, ChevronDown,
  Menu, User
} from 'lucide-react';
import { useTheme } from '../../context/themeContext';
import { UserSession } from '../../types';

interface HeaderProps {
  currentUser?: UserSession | null;
  openInvestigationsCount: number;
  systemStatus?: string;
  onLogout?: () => void;
  onToggleSidebar?: () => void;
  onSearch?: (query: string) => void;
  onOpenProfileSettings?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentUser,
  openInvestigationsCount,
  systemStatus,
  onLogout,
  onToggleSidebar,
  onSearch,
  onOpenProfileSettings,
}) => {
  const { theme, toggleTheme } = useTheme();
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [searchVal, setSearchVal] = useState('');

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSearch) onSearch(searchVal);
  };

  const getInitials = (name?: string) => {
    if (!name) return 'A';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .slice(0, 2)
      .toUpperCase();
  };

  return (
    <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-4 sm:px-6 py-2.5 flex items-center justify-between sticky top-0 z-30 transition-colors duration-200 shadow-xs">
      {/* Left: Mobile Sidebar Toggle & Search Bar */}
      <div className="flex items-center gap-3 flex-1 max-w-lg">
        <button
          onClick={onToggleSidebar}
          className="md:hidden p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
          aria-label="Toggle Navigation"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Global SOC Search Bar */}
        <form onSubmit={handleSearchSubmit} className="relative w-full max-w-md hidden sm:block">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search employees, threats, URLs, incidents..."
            value={searchVal}
            onChange={(e) => {
              setSearchVal(e.target.value);
              if (onSearch) onSearch(e.target.value);
            }}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500 transition-colors"
          />
        </form>
      </div>

      {/* Right Controls: System Status Badge, Theme Switcher, Notifications, User Profile */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* Platform status, from the server: database answering and automation worker reporting */}
        {(() => {
          const ok = systemStatus === 'Operational';
          const tone = ok
            ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/60'
            : 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/60';
          return (
            <div title={systemStatus ?? 'Checking…'} className={`hidden lg:flex items-center gap-2 text-xs border px-2.5 py-1 rounded-full font-medium ${tone}`}>
              <span className={`inline-flex rounded-full h-2 w-2 ${ok ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              <span className="text-[11px] font-semibold tracking-tight">{systemStatus === undefined ? 'Checking…' : ok ? 'Platform healthy' : 'Platform degraded'}</span>
            </div>
          );
        })()}

        {/* Light / Dark Mode Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
          aria-label="Toggle Theme"
        >
          {theme === 'light' ? (
            <Moon className="w-4 h-4 text-slate-700 transition transform hover:rotate-12" />
          ) : (
            <Sun className="w-4 h-4 text-amber-400 transition transform hover:rotate-45" />
          )}
        </button>

        {/* Notifications Bell */}
        <div className="relative">
          <button
            className="p-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition relative"
            title="Active Incidents & Alerts"
            aria-label="Notifications"
          >
            <Bell className="w-4 h-4" />
            {openInvestigationsCount > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white dark:ring-slate-900 animate-pulse"></span>
            )}
          </button>
        </div>

        {/* User Profile & Role Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2 pl-2 border-l border-slate-200 dark:border-slate-800 text-left hover:opacity-90 transition"
          >
            <div className="w-7 h-7 rounded-full bg-sky-600 dark:bg-sky-500 text-white flex items-center justify-center text-xs font-bold shadow-xs">
              {getInitials(currentUser?.name)}
            </div>
            <div className="hidden xl:block">
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100 leading-tight">
                {currentUser?.name || 'Admin'}
              </p>
              <p className="text-[10px] text-sky-600 dark:text-sky-400 font-semibold">
                {currentUser?.role || 'Super Admin'}
              </p>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 hidden sm:block" />
          </button>

          {/* Profile Menu Popup */}
          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-60 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-slate-200 dark:border-slate-700 py-2 z-50 text-xs text-slate-700 dark:text-slate-200 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="px-4 py-2 border-b border-slate-100 dark:border-slate-700/60">
                <p className="font-bold text-slate-900 dark:text-white">{currentUser?.name}</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate">{currentUser?.email}</p>
                <div className="mt-1.5 flex items-center gap-1.5">
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-sky-50 dark:bg-sky-950/70 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800">
                    {currentUser?.role}
                  </span>
                  <span className="text-[10px] text-slate-400 dark:text-slate-500">
                    {theme === 'dark' ? 'Dark Theme' : 'Light Theme'}
                  </span>
                </div>
              </div>

              <div className="py-1">
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    if (onOpenProfileSettings) onOpenProfileSettings();
                  }}
                  className="w-full px-4 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-700/60 flex items-center gap-2 text-slate-700 dark:text-slate-200 transition font-medium"
                >
                  <User className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
                  <span>Profile Settings</span>
                </button>

                <button
                  onClick={toggleTheme}
                  className="w-full px-4 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-700/60 flex items-center justify-between transition"
                >
                  <span className="flex items-center gap-2">
                    {theme === 'light' ? <Moon className="w-3.5 h-3.5" /> : <Sun className="w-3.5 h-3.5 text-amber-400" />}
                    <span>Theme: {theme === 'light' ? 'Light' : 'Dark'}</span>
                  </span>
                  <span className="text-[10px] text-slate-400 uppercase font-mono">Toggle</span>
                </button>
              </div>

              {onLogout && (
                <div className="pt-1 border-t border-slate-100 dark:border-slate-700/60">
                  <button
                    onClick={() => {
                      setShowProfileMenu(false);
                      onLogout();
                    }}
                    className="w-full px-4 py-2 text-left text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 flex items-center gap-2 transition font-medium"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out / Switch Role</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
