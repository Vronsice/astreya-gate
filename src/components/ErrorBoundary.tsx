import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

/*
  Страховка уровня приложения: краш одной страницы не должен опрокидывать
  весь shell (чёрный экран без сайдбара). Показываем причину и кнопку
  перезагрузки — данные на диске при этом не трогаются.
*/
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Ошибка интерфейса:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-full w-full items-center justify-center p-8">
          <div className="max-w-md rounded-xl border border-vb-loss/40 bg-vb-bg p-6 text-center">
            <div className="text-[15px] font-semibold text-vb-loss">
              Раздел упал с ошибкой
            </div>
            <p className="mt-2 break-words font-mono text-[12px] text-vb-silver-dim">
              {this.state.error.message}
            </p>
            <button
              type="button"
              onClick={() => location.reload()}
              className="mt-4 rounded-lg bg-vb-emerald px-4 py-2 text-[13px] font-semibold text-black transition-colors hover:bg-vb-emerald-bright"
            >
              Перезагрузить приложение
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
