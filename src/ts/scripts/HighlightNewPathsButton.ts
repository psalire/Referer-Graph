
import StyledButton from './StyledButton';

export default class HighlightNewPaths extends StyledButton {
    private isHighlightNewPathsOn: boolean=false;

    constructor() {
        super('', 'btn-secondary', true);
        this.setText(this.createIsHighlightNewPathsText(), true);
        this.addToggleValue('color', 'btn-success', 'btn-secondary');
        this.getButton().addEventListener('click', ()=>{
            this.isHighlightNewPathsOn = !this.isHighlightNewPathsOn;
            this.toggleStyle('color');
            this.setText(this.createIsHighlightNewPathsText(), true);
        });
    }

    public getIsHighlightNewPathsOn(): boolean {
        return this.isHighlightNewPathsOn;
    }
    private createIsHighlightNewPathsText(): string {
        return `Highlight New: <span class="fw-bold">${this.getIsHighlightNewPathsOn()?'ON':'OFF'}</span>`;
    }
}
