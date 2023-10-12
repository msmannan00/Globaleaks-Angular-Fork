import {Component} from "@angular/core";
import {AppDataService} from "@app/app-data.service";
import {HttpService} from "@app/shared/services/http.service";
import {UtilsService} from "app/src/shared/services/utils.service";

@Component({
  selector: "src-casemanagement-tab1",
  templateUrl: "./case-management-tab1.component.html"
})
export class CaseManagementTab1Component {
  showAddStatus = false;
  newSubmissionsStatus: any = {
    label: "",
  };

  constructor(private utilsService: UtilsService, public appDataServices: AppDataService, private appDataService: AppDataService, private httpService: HttpService) {
  }

  toggleAddStatus() {
    this.showAddStatus = !this.showAddStatus;
  };

  addSubmissionStatus() {
    let order = this.utilsService.newItemOrder(this.appDataServices.submissionStatuses, "order");
    const newSubmissionsStatus = {
      label: this.newSubmissionsStatus.label,
      order: order
    };

    this.httpService.addSubmissionStatus(newSubmissionsStatus).subscribe(
      result => {
        this.appDataService.submissionStatuses.push(result);
        this.newSubmissionsStatus.label = "";
      }
    );
  };
}
