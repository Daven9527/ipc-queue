import Link from "next/link";
import Image from "next/image";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex items-center justify-center p-4">
      <div className="w-full max-w-5xl text-center space-y-6 md:space-y-8">
        <div className="flex justify-center">
          <Image
            src="/MSI IPC_logo_Black_20240313.png"
            alt="MSI IPC Logo"
            width={240}
            height={80}
            className="h-auto w-48 md:w-60"
            priority
          />
        </div>
        <div>
          <h1 className="text-3xl md:text-5xl font-bold text-gray-900 mb-3 md:mb-4">IPC排隊系統</h1>
          <p className="text-base md:text-xl text-gray-600">Queue Management System</p>
        </div>

        <div className="grid gap-4 md:gap-6 md:grid-cols-3">
          <Link
            href="/ticket"
            className="rounded-xl bg-white p-6 md:p-8 shadow-lg hover:shadow-xl transition-shadow"
          >
            <div className="text-3xl md:text-4xl mb-3 md:mb-4">🎫</div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-2">抽號服務</h2>
            <p className="text-sm md:text-base text-gray-600">填寫資訊取得號碼牌</p>
          </Link>

          <Link
            href="/display"
            className="rounded-xl bg-white p-6 md:p-8 shadow-lg hover:shadow-xl transition-shadow"
          >
            <div className="text-3xl md:text-4xl mb-3 md:mb-4">📺</div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-2">顧客顯示頁</h2>
            <p className="text-sm md:text-base text-gray-600">即時顯示目前叫號</p>
          </Link>

          <Link
            href="/admin"
            className="rounded-xl bg-white p-6 md:p-8 shadow-lg hover:shadow-xl transition-shadow"
          >
            <div className="text-3xl md:text-4xl mb-3 md:mb-4">⚙️</div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-2">PM 管理平台</h2>
            <p className="text-sm md:text-base text-gray-600">發號、叫號、資料維護</p>
          </Link>

          <Link
            href="/super-admin"
            className="rounded-xl bg-white p-6 md:p-8 shadow-lg hover:shadow-xl transition-shadow"
          >
            <div className="text-3xl md:text-4xl mb-3 md:mb-4">🛡️</div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-2">管理員控制台</h2>
            <p className="text-sm md:text-base text-gray-600">超級管理員與帳號管理</p>
          </Link>
        </div>
      </div>
    </div>
  );
}
