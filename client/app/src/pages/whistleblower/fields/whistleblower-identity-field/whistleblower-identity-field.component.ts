import {Component, EventEmitter, Input, OnInit, Output} from "@angular/core";
import {ControlContainer, NgForm} from "@angular/forms";
import { WhistleblowerIdentity } from "@app/models/app/shared-public-model";
import { Answers } from "@app/models/reciever/reciever-tip-data";
import { Field } from "@app/models/resolvers/field-template-model";
import { Step } from "@app/models/whistleblower/wb-tip-data";
import { SubmissionService } from "@app/services/submission.service";

@Component({
  selector: "src-whistleblower-identity-field",
  templateUrl: "./whistleblower-identity-field.component.html",
  viewProviders: [{provide: ControlContainer, useExisting: NgForm}]
})
export class WhistleblowerIdentityFieldComponent implements OnInit {
  @Input() submission: SubmissionService;
  @Input() field: Field;
  @Output() stateChanged = new EventEmitter<boolean>();

  @Input() stepId: string;
  @Input() fieldCol: number;
  @Input() fieldRow: number;
  @Input() index: number;
  @Input() step: Step;
  @Input() answers: Answers;
  @Input() entry: string;
  @Input() fields: Field;
  @Input() displayErrors: boolean;
  @Input() identity_provided: boolean = false;

  ngOnInit(): void {
    this.identity_provided = true;
    this.stateChanged.emit(true);
    if (this.submission) {
      this.submission._submission.identity_provided = true;
    }
  }

  changeIdentitySetting(status: boolean): void {
    this.identity_provided = status;
    if (this.submission) {
      this.submission._submission.identity_provided = status;
    }
    this.stateChanged.emit(status);
  }
}
