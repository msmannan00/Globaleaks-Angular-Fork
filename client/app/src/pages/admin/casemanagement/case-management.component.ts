import {Component, TemplateRef, ViewChild, AfterViewInit, ChangeDetectorRef} from "@angular/core";
import { Tab } from "@app/models/component-model/tab";
import {NodeResolver} from "@app/shared/resolvers/node.resolver";

@Component({
  selector: "src-casemanagement",
  templateUrl: "./case-management.component.html"
})
export class CaseManagementComponent implements AfterViewInit {
  @ViewChild("tab1") tab1!: TemplateRef<any>;
  tabs: Tab[];
  nodeData: NodeResolver;
  active: string;

  constructor(protected node: NodeResolver, private cdr: ChangeDetectorRef) {
  }

  ngAfterViewInit(): void {
    setTimeout(() => {
      this.active = "Report statuses";

      this.nodeData = this.node;
      this.tabs = [
        {
          title: "Report statuses",
          component: this.tab1
        },
      ];

      this.cdr.detectChanges();
    });
  }
}
