package com.imom.crypto.util;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class XlseUtility {

    public static void createExcel(String tenantId,String dbpwd) {
        List<Map<String,Object>> activities = KeyGen.getActivityLogs(tenantId,dbpwd,true);
        if(activities != null) {
            XSSFWorkbook workbook = new XSSFWorkbook();
            XSSFSheet sheet = workbook.createSheet("ActivitesLogs");
            Font headerFont = workbook.createFont();
            CellStyle headerCellStyle = workbook.createCellStyle();
            headerFont.setBold(true);
            headerFont.setFontHeightInPoints((short) 10);
            headerFont.setColor(IndexedColors.BLACK.getIndex());
            headerCellStyle.setFont(headerFont);
            int rownum = 0;
            Row headRow = getRow(sheet, rownum++);
            headRow.setRowStyle(headerCellStyle);
            int cellNum = 0;
            for (String s : Arrays.asList("Action By","Action Type","Action Performed on (UTC)","IP Address")) {
                Cell cell = headRow.createCell(cellNum++);
                cell.setCellValue(s);
            }

            for (Map<String,Object> maps: activities) {
                Row row = getRow(sheet, rownum++);
                cellNum = 0;
                for (String keys : Arrays.asList("userId","actionType","actionDate","ipAddress")) {
                    Cell cell = row.createCell(cellNum++);
                    cell.setCellValue(maps.get(keys).toString());
                }

            }

            try {
                FileOutputStream out = new FileOutputStream(new File("ActivitiesLogs.xlsx"));
                workbook.write(out);
                out.close();
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
    }

    private static Row getRow(XSSFSheet sheet, int rowNumber) {
        if (sheet.getRow(rowNumber) != null)
            return sheet.getRow(rowNumber);
        return sheet.createRow(rowNumber);
    }
}
