package yara.docscan.android.ui;

import android.app.Activity;
import android.text.format.DateUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;

import yara.docscan.android.R;
import yara.docscan.android.watch.FileIndex;

/** "Журнал": what the watcher scanned and found; a tap shows the full JSON record. */
public final class JournalTab {
    private final Activity a;
    private final ExecutorService bg;
    private final TextView empty;
    private final CompoundButton onlyThreats;
    private final Adapter adapter = new Adapter();

    public JournalTab(Activity a, View root, ExecutorService bg) {
        this.a = a;
        this.bg = bg;
        empty = root.findViewById(R.id.empty);
        onlyThreats = root.findViewById(R.id.filter);
        onlyThreats.setOnCheckedChangeListener((b, on) -> refresh());
        RecyclerView list = root.findViewById(R.id.list);
        list.setLayoutManager(new LinearLayoutManager(a));
        list.setAdapter(adapter);
    }

    public void refresh() {
        boolean threats = onlyThreats.isChecked();
        bg.execute(() -> {
            List<FileIndex.Event> ev = FileIndex.get(a).events(500, threats);
            a.runOnUiThread(() -> {
                adapter.set(ev);
                empty.setVisibility(ev.isEmpty() ? View.VISIBLE : View.GONE);
                empty.setText(R.string.journal_empty);
            });
        });
    }

    private void show(FileIndex.Event e) {
        String body;
        try {
            body = new JSONObject(e.json).toString(2);
        } catch (Exception ex) {
            body = e.json;
        }
        TextView tv = new TextView(a);
        tv.setText(body);
        tv.setTextIsSelectable(true);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        tv.setTextSize(11);
        int pad = (int) (16 * a.getResources().getDisplayMetrics().density);
        tv.setPadding(pad, pad, pad, pad);
        android.widget.ScrollView sv = new android.widget.ScrollView(a);
        sv.addView(tv);
        new AlertDialog.Builder(a).setTitle(e.subject).setView(sv).setPositiveButton(R.string.close, null).show();
    }

    private final class Adapter extends RecyclerView.Adapter<Holder> {
        private final List<FileIndex.Event> items = new ArrayList<>();

        void set(List<FileIndex.Event> ev) {
            items.clear();
            items.addAll(ev);
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_event, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull Holder h, int pos) {
            FileIndex.Event e = items.get(pos);
            Ui.badge(h.badge, e.verdict);
            h.title.setText("file".equals(e.kind) ? new File(e.subject).getName() : e.subject);
            h.summary.setText(e.summary == null || e.summary.isEmpty() ? a.getString(R.string.nothing_found) : e.summary);
            h.meta.setText(DateUtils.getRelativeTimeSpanString(e.time) + " · "
                    + ("file".equals(e.kind) ? e.subject : e.kind));
            h.itemView.setOnClickListener(v -> show(e));
        }

        @Override
        public int getItemCount() {
            return items.size();
        }
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final TextView badge, title, summary, meta;

        Holder(View v) {
            super(v);
            badge = v.findViewById(R.id.badge);
            title = v.findViewById(R.id.title);
            summary = v.findViewById(R.id.summary);
            meta = v.findViewById(R.id.meta);
        }
    }
}
