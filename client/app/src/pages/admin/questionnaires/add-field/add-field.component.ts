import {Component, EventEmitter, Input, OnInit, Output} from "@angular/core";
import {HttpService} from "@app/shared/services/http.service";
import {UtilsService} from "@app/shared/services/utils.service";
import {new_field} from "@app/models/admin/new_field";
import {field_template} from "@app/models/admin/fieldTemplate";
import {QuestionnaireService} from "@app/pages/admin/questionnaires/questionnaire.service";

@Component({
  selector: "src-add-field",
  templateUrl: "./add-field.component.html"
})
export class AddFieldComponent implements OnInit {
  @Output() dataToParent = new EventEmitter<string>();
  @Input() step: any;
  @Input() type: any;
  new_field: any = {};
  fields: any;

  constructor(private questionnaireService: QuestionnaireService, private httpService: HttpService, private utilsService: UtilsService) {
    this.new_field = {
      label: "",
      type: ""
    };
  }

  ngOnInit(): void {
    if (this.step) {
      this.fields = this.step.children;
    }
  }

  add_field() {
    if (this.type === "step") {

      const field = new new_field();
      field.step_id = this.step.id;
      field.template_id = "";
      field.label = this.new_field.label;
      field.type = this.new_field.type;
      field.y = this.utilsService.newItemOrder(this.fields, "y");

      if (field.type === "fileupload") {
        field.multi_entry = true;
      }
      this.httpService.requestAddAdminQuestionnaireField(field).subscribe((newField: any) => {
        this.fields.push(newField);
        this.new_field = {
          label: "",
          type: ""
        };
        this.dataToParent.emit();
        return this.questionnaireService.sendData();
      });
    }
    if (this.type === "template") {
      const field = new field_template();
      field.fieldgroup_id = this.fields ? this.fields.id : "";
      field.instance = "template";
      field.label = this.new_field.label;
      field.type = this.new_field.type;
      this.httpService.requestAddAdminQuestionnaireFieldTemplate(field).subscribe((_: any) => {
        this.new_field = {
          label: "",
          type: ""
        };
        this.dataToParent.emit();
        return this.questionnaireService.sendData();
      });
    }
    if (this.type === "field") {

      const field = new new_field();
      field.fieldgroup_id = this.step.id;
      field.template_id = "";

      field.label = this.new_field.label;
      field.type = this.new_field.type;
      field.y = this.utilsService.newItemOrder(this.step.children, "y");

      if (field.type === "fileupload") {
        field.multi_entry = true;
      }
      field.instance = this.step.instance;
      this.httpService.requestAddAdminQuestionnaireField(field).subscribe((newField: any) => {
        this.step.children.push(newField);
        this.new_field = {
          label: "",
          type: ""
        };
        this.dataToParent.emit();
        return this.questionnaireService.sendData();
      });
    }
  }
}