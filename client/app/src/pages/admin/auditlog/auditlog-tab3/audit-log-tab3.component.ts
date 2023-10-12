import {Component} from "@angular/core";
import {UtilsService} from "@app/shared/services/utils.service";
import {ngxCsv} from "ngx-csv";
import {TipsResolver} from "@app/shared/resolvers/tips.resolver";
import {tipsResolverModel} from "@app/models/resolvers/tipsResolverModel";
import {AppDataService} from "@app/app-data.service";

@Component({
  selector: "src-auditlog-tab3",
  templateUrl: "./audit-log-tab3.component.html"
})
export class AuditLogTab3Component {
  currentPage = 1;
  pageSize = 20;
  tips: any = new tipsResolverModel();

  constructor(private tipsResolver: TipsResolver, public utilsService: UtilsService, public appDataService: AppDataService) {
  }

  ngOnInit() {
    this.loadAuditLogData();
  }

  loadAuditLogData() {
    this.tips = this.tipsResolver.dataModel;
  }

  getPaginatedData(): any[] {
    const startIndex = (this.currentPage - 1) * this.pageSize;
    const endIndex = startIndex + this.pageSize;
    return this.tips.slice(startIndex, endIndex);
  }

  exportAuditLog() {
    new ngxCsv(JSON.stringify(this.tips), "reports", {
      headers: ["id", "progressive", "creation_date", "last_update", "expiration_date", "context_id", "status", "substatus", "tor", "comments", "files", "last_access"],
    });
  }
}
