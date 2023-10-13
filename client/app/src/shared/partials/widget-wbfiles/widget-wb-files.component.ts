import {Component, Input} from "@angular/core";
import {WbtipService} from "@app/services/wbtip.service";
import {UtilsService} from "../../services/utils.service";

@Component({
  selector: "src-widget-wbfiles",
  templateUrl: "./widget-wb-files.component.html"
})
export class WidgetWbFilesComponent {

  @Input() index: any;
  @Input() ctx: any;
  @Input() receivers_by_id: any;

  collapsed = false;
  submission = {};

  constructor(public wbTipService: WbtipService, public utilsService: UtilsService) {
  }

  public toggleCollapse() {
    this.collapsed = !this.collapsed;
  }
}
