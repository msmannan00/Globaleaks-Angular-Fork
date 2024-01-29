import {Component, EventEmitter, Input, OnInit, Output} from "@angular/core";
import {UtilsService} from "@app/shared/services/utils.service";
import {ControlContainer, NgForm} from "@angular/forms";
import {SubmissionService} from "@app/services/helper/submission.service";
import {Answers} from "@app/models/reciever/reciever-tip-data";
import {Step} from "@app/models/whistleblower/wb-tip-data";
import {Field} from "@app/models/resolvers/field-template-model";
import {cloneDeep} from "lodash";

@Component({
  selector: "src-form-field-inputs",
  templateUrl: "./form-field-inputs.component.html",
  viewProviders: [{provide: ControlContainer, useExisting: NgForm}],
})
export class FormFieldInputsComponent implements OnInit {
  @Input() field: Field;
  @Input() fieldRow: number;
  @Input() fieldCol: number;
  @Input() stepId: string;
  @Input() step: Step;
  @Input() entry: string;
  @Input() answers: Answers;
  @Input() submission: SubmissionService;
  @Input() index: number;
  @Input() displayErrors: boolean;
  @Input() fields: any;
  @Input() uploads: { [key: string]: any };
  @Input() identity_provided: boolean;
  @Input() fileUploadUrl: string;
  @Input() fieldEntry: string;
  @Output() notifyFileUpload: EventEmitter<any> = new EventEmitter<any>();

  fieldId: string;
  entries: { [key: string]: Field }[] = [];

  constructor(protected utilsService: UtilsService) {
  }

  ngOnInit(): void {
    if(!this.fieldEntry){
      this.fieldId = this.stepId + "-field-" + this.fieldRow + "-" + this.fieldCol;
      this.fieldEntry = this.fieldId + "-input-" + this.index;
    }else {
      this.fieldId = "-field-" + this.fieldRow + "-" + this.fieldCol;
      this.fieldEntry += this.fieldId + "-input-" + this.index;
    }

    this.entries = this.getAnswersEntries(this.entry);

    if(!this.fieldEntry){
      this.fieldEntry = "";
    }
  }

  getAnswersEntries(entry: any) {
    if (typeof entry === "undefined") {
      return this.answers[this.field.id];
    }

    return entry[this.field.id];
  };

  addAnswerEntry(entries:any) {
    let newEntry = cloneDeep(entries[0]);
    for (let key in newEntry) {
      if (newEntry.hasOwnProperty(key)) {
        if (Array.isArray(newEntry[key]) && newEntry[key].length > 0) {
          newEntry[key][0].value = "";
        }
      }
    }
    console.log("adssdasdasads")

    entries.push(newEntry);
  };

}
