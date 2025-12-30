import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";
import * as XLSX from "xlsx";

export const dynamic = "force-dynamic";

const IMPORT_PASSWORD = "Eunice";

export async function POST(request: Request) {
  try {
    // 解析 multipart/form-data
    const formData = await request.formData();
    const file = formData.get("file") as File;
    const password = formData.get("password") as string;

    // 驗證密碼
    if (password !== IMPORT_PASSWORD) {
      return NextResponse.json(
        { error: "密碼錯誤" },
        { status: 401 }
      );
    }

    if (!file) {
      return NextResponse.json(
        { error: "請選擇要匯入的檔案" },
        { status: 400 }
      );
    }

    // 讀取文件內容
    const arrayBuffer = await file.arrayBuffer();
    const workbook = XLSX.read(arrayBuffer, { type: "array" });

    // 獲取第一個工作表
    const firstSheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[firstSheetName];

    // 將工作表轉換為 JSON
    const data = XLSX.utils.sheet_to_json(worksheet, { header: 1 }) as any[][];

    if (data.length < 2) {
      return NextResponse.json(
        { error: "Excel 文件格式錯誤，至少需要標題行和一行資料" },
        { status: 400 }
      );
    }

    // 第一行是標題，跳過
    const headers = data[0] as string[];
    const rows = data.slice(1);

    // 找到各欄位的索引
    const ticketNumberIndex = headers.findIndex(h => h === "號碼" || h === "票號" || h === "ticketNumber");
    const applicantIndex = headers.findIndex(h => h === "申請人" || h === "applicant");
    const customerNameIndex = headers.findIndex(h => h === "客戶名稱" || h === "客戶姓名" || h === "customerName");
    const customerRequirementIndex = headers.findIndex(h => h === "客戶需求" || h === "需求" || h === "customerRequirement");
    const machineTypeIndex = headers.findIndex(h => h === "預計使用機種" || h === "機種" || h === "machineType");
    const startDateIndex = headers.findIndex(h => h === "起始日期" || h === "startDate");
    const expectedCompletionDateIndex = headers.findIndex(h => h === "期望完成日期" || h === "完成日期" || h === "expectedCompletionDate");
    const statusIndex = headers.findIndex(h => h === "處理進度" || h === "狀態" || h === "status");
    const noteIndex = headers.findIndex(h => h === "備註" || h === "備註說明" || h === "note");
    const assigneeIndex = headers.findIndex(h => h === "PM" || h === "處理者" || h === "assignee");
    const fcstIndex = headers.findIndex(h => h === "FCST" || h === "fcst");
    const massProductionDateIndex = headers.findIndex(h => h === "預計量產日" || h === "massProductionDate" || h === "量產日");

    if (ticketNumberIndex === -1) {
      return NextResponse.json(
        { error: "Excel 文件必須包含「號碼」欄位" },
        { status: 400 }
      );
    }

    let importedCount = 0;
    let updatedCount = 0;
    const errors: string[] = [];

    // 處理每一行資料
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (!row || row.length === 0) continue;

      try {
        const ticketNumber = Number(row[ticketNumberIndex]);
        if (isNaN(ticketNumber) || ticketNumber <= 0) {
          errors.push(`第 ${i + 2} 行：號碼無效`);
          continue;
        }

        // 檢查票券是否已存在
        const key = `queue:ticket:${ticketNumber}`;
        const existingData = await redis.hgetall(key);
        const isNew = !existingData || Object.keys(existingData).length === 0;

        // 準備要儲存的資料
        const ticketData: Record<string, string> = {
          applicant: row[applicantIndex]?.toString() || "",
          customerName: row[customerNameIndex]?.toString() || "",
          customerRequirement: row[customerRequirementIndex]?.toString() || "",
          machineType: row[machineTypeIndex]?.toString() || "",
          startDate: row[startDateIndex]?.toString() || "",
          expectedCompletionDate: row[expectedCompletionDateIndex]?.toString() || "",
          status: row[statusIndex]?.toString() || "pending",
          note: row[noteIndex]?.toString() || "",
          assignee: row[assigneeIndex]?.toString() || "",
          fcst: row[fcstIndex]?.toString() || "",
          massProductionDate: row[massProductionDateIndex]?.toString() || "",
        };

        // 驗證狀態值
        const validStatuses = ["pending", "processing", "replied", "completed", "cancelled"];
        if (!validStatuses.includes(ticketData.status)) {
          ticketData.status = "pending";
        }

        // 儲存到 Redis
        await redis.hset(key, ticketData);

        // 如果是新票券，添加到票券列表和更新 lastTicket
        if (isNew) {
          // 檢查票券號碼是否已在列表中
          const existingTickets = await redis.lrange<number>("queue:tickets", 0, -1);
          const ticketExists = existingTickets && existingTickets.some(t => Number(t) === ticketNumber);
          
          if (!ticketExists) {
            await redis.rpush("queue:tickets", ticketNumber);
          }
          
          // 更新 lastTicket
          const currentLast = (await redis.get<number>("queue:last")) ?? 0;
          if (ticketNumber > currentLast) {
            await redis.set("queue:last", ticketNumber);
          }
          
          importedCount++;
        } else {
          updatedCount++;
        }
      } catch (error) {
        errors.push(`第 ${i + 2} 行：處理失敗 - ${error instanceof Error ? error.message : "未知錯誤"}`);
      }
    }

    return NextResponse.json({
      success: true,
      imported: importedCount,
      updated: updatedCount,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    console.error("Error importing from Excel:", error);
    return NextResponse.json(
      { error: "匯入失敗" },
      { status: 500 }
    );
  }
}


