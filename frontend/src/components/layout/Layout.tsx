import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Moon, Sun, FileSearch, Home } from 'lucide-react';
import { useTheme } from '../../lib/theme';

export default function Layout() {
  const { theme, setTheme } = useTheme();
  const location = useLocation();

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: Home },
    { name: 'Scans', href: '/scans', icon: FileSearch },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center px-4">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-bold">SecScan Pro</h1>
          </div>

          <nav className="ml-10 flex gap-6">
            {navigation.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname.startsWith(item.href);
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center gap-2 text-sm font-medium transition-colors hover:text-primary ${
                    isActive ? 'text-primary' : 'text-muted-foreground'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-4">
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="rounded-md p-2 hover:bg-accent"
            >
              {theme === 'dark' ? (
                <Sun className="h-5 w-5" />
              ) : (
                <Moon className="h-5 w-5" />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container py-6 px-4">
        <Outlet />
      </main>
    </div>
  );
}
