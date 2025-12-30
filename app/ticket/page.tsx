"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function TicketPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    applicant: "",
    customerName: "",
    customerRequirement: "",
    machineType: "",
    startDate: "",
    expectedCompletionDate: "",
    fcst: "",
    massProductionDate: "",
  });
  const [loading, setLoading] = useState(false);
  const [ticketNumber, setTicketNumber] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/ticket", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "抽號失敗");
      }

      setTicketNumber(data.ticketNumber);
    } catch (err) {
      setError(err instanceof Error ? err.message : "抽號失敗，請重試");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setTicketNumber(null);
    setFormData({
      applicant: "",
      customerName: "",
      customerRequirement: "",
      machineType: "",
      startDate: "",
      expectedCompletionDate: "",
      fcst: "",
      massProductionDate: "",
    });
    setError(null);
  };

  if (ticketNumber) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 flex items-center justify-center p-4">
        <div className="w-full max-w-2xl">
          <div className="rounded-2xl bg-white p-6 md:p-12 shadow-2xl text-center">
            <div className="mb-4 md:mb-6">
              <div className="text-5xl md:text-6xl mb-3 md:mb-4">✅</div>
              <h2 className="text-2xl md:text-3xl font-bold text-gray-900 mb-2">
                抽號成功！
              </h2>
            </div>
            <div className="mb-6 md:mb-8">
              <p className="text-base md:text-lg text-gray-600 mb-3 md:mb-4">您的號碼是</p>
              <div className="text-6xl md:text-8xl font-bold text-blue-600 mb-4 md:mb-6">
                {ticketNumber}
              </div>
            </div>
            <div className="bg-gray-50 rounded-xl p-4 md:p-6 mb-6 md:mb-8 text-left">
              <h3 className="text-base md:text-lg font-semibold text-gray-800 mb-3 md:mb-4">
                您的資訊
              </h3>
              <div className="space-y-2 md:space-y-3">
                <div>
                  <p className="text-xs md:text-sm text-gray-600">申請人</p>
                  <p className="text-sm md:text-base font-medium text-gray-900 break-words">
                    {formData.applicant}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">客戶名稱</p>
                  <p className="text-sm md:text-base font-medium text-gray-900 break-words">
                    {formData.customerName}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">客戶需求</p>
                  <p className="text-sm md:text-base font-medium text-gray-900 break-words">
                    {formData.customerRequirement}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">預計使用機種</p>
                  <p className="text-sm md:text-base font-medium text-gray-900 break-words">
                    {formData.machineType}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">起始日期</p>
                  <p className="text-sm md:text-base font-medium text-gray-900">
                    {formData.startDate}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">期望完成日期</p>
                  <p className="text-sm md:text-base font-medium text-gray-900">
                    {formData.expectedCompletionDate}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">FCST</p>
                  <p className="text-sm md:text-base font-medium text-gray-900 break-words">
                    {formData.fcst}
                  </p>
                </div>
                <div>
                  <p className="text-xs md:text-sm text-gray-600">預計量產日</p>
                  <p className="text-sm md:text-base font-medium text-gray-900">
                    {formData.massProductionDate}
                  </p>
                </div>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 md:gap-4">
              <button
                onClick={handleReset}
                className="flex-1 rounded-lg bg-gray-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-gray-700 transition-colors"
              >
                再抽一張
              </button>
              <button
                onClick={() => router.push("/display")}
                className="flex-1 rounded-lg bg-blue-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-blue-700 transition-colors"
              >
                查看叫號
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-4 md:p-8">
      <div className="mx-auto max-w-2xl">
        <div className="mb-6 md:mb-8 text-center">
          <h1 className="text-2xl md:text-4xl font-bold text-gray-900 mb-2">抽號服務</h1>
          <p className="text-sm md:text-base text-gray-600">請填寫以下資訊以取得號碼牌</p>
        </div>

        <div className="rounded-xl bg-white p-4 md:p-8 shadow-lg">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label
                htmlFor="applicant"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                申請人 <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="applicant"
                name="applicant"
                value={formData.applicant}
                onChange={handleChange}
                required
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                placeholder="請輸入申請人姓名"
              />
            </div>

            <div>
              <label
                htmlFor="customerName"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                客戶名稱 <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="customerName"
                name="customerName"
                value={formData.customerName}
                onChange={handleChange}
                required
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                placeholder="請輸入客戶名稱"
              />
            </div>

            <div>
              <label
                htmlFor="customerRequirement"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                客戶需求 <span className="text-red-500">*</span>
              </label>
              <textarea
                id="customerRequirement"
                name="customerRequirement"
                value={formData.customerRequirement}
                onChange={handleChange}
                required
                rows={4}
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors resize-none"
                placeholder="請描述客戶需求"
              />
            </div>

            <div>
              <label
                htmlFor="machineType"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                預計使用機種 <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="machineType"
                name="machineType"
                value={formData.machineType}
                onChange={handleChange}
                required
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                placeholder="請輸入機種名稱"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  htmlFor="fcst"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  FCST <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  id="fcst"
                  name="fcst"
                  value={formData.fcst}
                  onChange={handleChange}
                  required
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 placeholder:text-gray-400 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                  placeholder="請輸入 FCST"
                />
              </div>

              <div>
                <label
                  htmlFor="massProductionDate"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  預計量產日 <span className="text-red-500">*</span>
                </label>
                <input
                  type="date"
                  id="massProductionDate"
                  name="massProductionDate"
                  value={formData.massProductionDate}
                  onChange={handleChange}
                  required
                  className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="startDate"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                起始日期 <span className="text-red-500">*</span>
              </label>
              <input
                type="date"
                id="startDate"
                name="startDate"
                value={formData.startDate}
                onChange={handleChange}
                required
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
              />
            </div>

            <div>
              <label
                htmlFor="expectedCompletionDate"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                期望完成日期 <span className="text-red-500">*</span>
              </label>
              <input
                type="date"
                id="expectedCompletionDate"
                name="expectedCompletionDate"
                value={formData.expectedCompletionDate}
                onChange={handleChange}
                required
                className="w-full rounded-lg border border-gray-300 px-4 py-3 text-gray-900 bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-colors"
              />
            </div>

            {error && (
              <div className="rounded-lg bg-red-50 border border-red-200 p-4">
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3 md:gap-4 pt-4">
              <button
                type="button"
                onClick={() => router.push("/")}
                className="flex-1 rounded-lg bg-gray-200 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-gray-800 font-medium hover:bg-gray-300 transition-colors"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 rounded-lg bg-blue-600 px-4 md:px-6 py-2.5 md:py-3 text-sm md:text-base text-white font-medium shadow-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? "處理中..." : "抽號"}
              </button>
            </div>
          </form>
        </div>

        <div className="mt-4 md:mt-6 text-center">
          <a
            href="/display"
            className="text-sm md:text-base text-blue-600 hover:text-blue-800 underline"
          >
            查看目前叫號狀況
          </a>
        </div>
      </div>
    </div>
  );
}

