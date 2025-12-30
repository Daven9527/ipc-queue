import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";
import * as XLSX from "xlsx";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    // 獲取所有票券號碼
    const raw = await redis.lrange<number>("queue:tickets", 0, -1);
    const ticketNumbers: number[] = (raw ?? [])
      .map((x: any) => Number(x))
      .filter((n) => Number.isFinite(n));

    if (ticketNumbers.length === 0) {
      return NextResponse.json(
        { error: "沒有票券資料可以匯出" },
        { status: 404 }
      );
    }

    // 獲取每個票券的詳細資訊
    const ticketsData = await Promise.all(
      ticketNumbers.map(async (ticketNumber) => {
        const key = `queue:ticket:${ticketNumber}`;
        const data = await redis.hgetall<{
          applicant?: string;
          customerName?: string;
          customerRequirement?: string;
          machineType?: string;
          startDate?: string;
          expectedCompletionDate?: string;
          fcst?: string;
          massProductionDate?: string;
          status?: string;
          note?: string;
          assignee?: string;
        }>(key);

        return {
          號碼: ticketNumber,
          申請人: data?.applicant || "",
          客戶名稱: data?.customerName || "",
          客戶需求: data?.customerRequirement || "",
          預計使用機種: data?.machineType || "",
          起始日期: data?.startDate || "",
          期望完成日期: data?.expectedCompletionDate || "",
          FCST: data?.fcst || "",
          預計量產日: data?.massProductionDate || "",
          處理進度: data?.status || "pending",
          備註: data?.note || "",
          PM: data?.assignee || "",
        };
      })
    );

    // 創建 Excel 工作簿
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(ticketsData);

    // 設置列寬
    const colWidths = [
      { wch: 10 }, // 號碼
      { wch: 15 }, // 申請人
      { wch: 20 }, // 客戶名稱
      { wch: 30 }, // 客戶需求
      { wch: 20 }, // 預計使用機種
      { wch: 15 }, // 起始日期
      { wch: 15 }, // 期望完成日期
      { wch: 12 }, // FCST
      { wch: 15 }, // 預計量產日
      { wch: 12 }, // 處理進度
      { wch: 30 }, // 備註
      { wch: 12 }, // PM
    ];
    worksheet["!cols"] = colWidths;

    XLSX.utils.book_append_sheet(workbook, worksheet, "票券資料");

    // 生成 Excel 文件緩衝區
    const excelBuffer = XLSX.write(workbook, {
      type: "buffer",
      bookType: "xlsx",
    });

    // 生成文件名（包含當前日期時間）
    const now = new Date();
    const fileName = `票券資料_${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(now.getDate()).padStart(2, "0")}${String(now.getHours()).padStart(2, "0")}${String(now.getMinutes()).padStart(2, "0")}.xlsx`;

    // 返回 Excel 文件
    return new NextResponse(excelBuffer, {
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="${encodeURIComponent(fileName)}"`,
      },
    });
  } catch (error) {
    console.error("Error exporting to Excel:", error);
    return NextResponse.json(
      { error: "匯出失敗" },
      { status: 500 }
    );
  }
}

