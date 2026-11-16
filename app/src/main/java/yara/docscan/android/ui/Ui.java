package yara.docscan.android.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import yara.docscan.android.R;

/** Small view helpers shared by the tabs. */
final class Ui {
    private Ui() {}

    static int verdictColor(Context ctx, String verdict) {
        int id;
        switch (verdict == null ? "" : verdict) {
            case "HIGH": case "bad": id = R.color.verdict_high; break;
            case "MEDIUM": case "warn": id = R.color.verdict_medium; break;
            case "INFO": case "ok": id = R.color.verdict_info; break;
            default: id = R.color.verdict_other;
        }
        return ContextCompat.getColor(ctx, id);
    }

    static void badge(TextView v, String verdict) {
        v.setText(verdict);
        v.setBackgroundColor(verdictColor(v.getContext(), verdict));
    }

    /** item_row: a coloured mark, a title, a detail and an optional button. */
    static View row(ViewGroup parent, String status, String title, String detail, String button,
                    View.OnClickListener onClick) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_row, parent, false);
        v.findViewById(R.id.mark).setBackgroundColor(verdictColor(parent.getContext(), status));
        ((TextView) v.findViewById(R.id.title)).setText(title);
        ((TextView) v.findViewById(R.id.detail)).setText(detail);
        Button b = v.findViewById(R.id.button);
        if (button != null) {
            b.setVisibility(View.VISIBLE);
            b.setText(button);
            b.setOnClickListener(onClick);
        }
        parent.addView(v);
        return v;
    }
}
